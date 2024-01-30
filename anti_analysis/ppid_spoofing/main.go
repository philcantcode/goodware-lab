package main

import (
	"flag"
	"fmt"
	"log"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var modadvapi32 = windows.NewLazySystemDLL("advapi32.dll")
var modkernel32 = windows.NewLazySystemDLL("kernel32.dll")
var procUpdateProcThreadAttribute = modkernel32.NewProc("UpdateProcThreadAttribute")
var procCreateProcessW = modkernel32.NewProc("CreateProcessW")
var procInitializeProcThreadAttributeList = modkernel32.NewProc("InitializeProcThreadAttributeList")

var (
	errERROR_IO_PENDING error = syscall.Errno(errnoERROR_IO_PENDING)
	errERROR_EINVAL     error = syscall.EINVAL
)

const (
	errnoERROR_IO_PENDING                = 997
	PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = 0x00020000
)

type StartupInfoEx struct {
	windows.StartupInfo
	AttributeList *PROC_THREAD_ATTRIBUTE_LIST
}

type PROC_THREAD_ATTRIBUTE_LIST struct {
	dwFlags  uint32
	size     uint64
	count    uint64
	reserved uint64
	unknown  *uint64
	entries  []*PROC_THREAD_ATTRIBUTE_ENTRY
}

type PROC_THREAD_ATTRIBUTE_ENTRY struct {
	attribute *uint32
	cbSize    uintptr
	lpValue   uintptr
}

func main() {
	payload := flag.String("payload", "C:\\Program Files (x86)\\Jagex Launcher\\JagexLauncher.exe", "Parent argument")
	parentPPID := flag.Int("parent-ppid", 0, "Parent process PID")
	flag.Parse()

	fmt.Printf("Payload (process) to be started: %s\n", *payload)

	// Handle = uintptr
	// Could only get handles to processes that of integrity level Medium or lower
	parentHandle, err := OpenHandle(*parentPPID)
	if err != nil {
		log.Fatalf("Error opening handle to parent process: %s", err)
	}
	defer syscall.CloseHandle(parentHandle)
	fmt.Printf("Parent PID to be set as payload's parent: %d\n", parentHandle)

	/*
		An attribute list is a data structures that stores a list of attributes
		associated with a process or thread. These attributes store information
		such as the priority, scheduling algorith, state, CPU affinity and memory
		address space.
	*/
	var lpSize uintptr = 0

	/*
		To initialize a PROC_THREAD_ATTRIBUTE_LIST, we need to call
		InitializeProcThreadAttributeList twice. The first call is to get the
		size of the list. The second call is to initialize the list.
	*/
	InitializeProcThreadAttributeList(nil, 1, 0, &lpSize)
	var pThreadAttribList PROC_THREAD_ATTRIBUTE_LIST

	//fmt.Printf("sThreadAttList: %+v\n", pThreadAttribList)
	fmt.Printf("lpSize: %d\n", lpSize)

	// attribListBytes := make([]byte, lpSize)
	// pThreadAttribList := (*PROC_THREAD_ATTRIBUTE_LIST)(unsafe.Pointer(&attribListBytes[0]))
	fmt.Printf("--> pThreadAttribList: %+v\n", pThreadAttribList)

	// dwAttributeSize = 1 because we only need 1 attrib list
	err = InitializeProcThreadAttributeList(&pThreadAttribList, 1, 0, &lpSize)
	if err != nil {
		log.Fatalf("Error initializing thread attribute list: %s", err)
	}

	fmt.Printf("pThreadAttribList Size: %d bytes\n", unsafe.Sizeof(pThreadAttribList))

	// Cast to uintptr (HANDLE is a uintptr)
	var parentHandlePtr uintptr = uintptr(parentHandle)
	var sizeOfParentHandlePtr uintptr = unsafe.Sizeof(&parentHandlePtr)

	// Update individual parameters - in this case, the parent procese (PPID)
	err = UpdateProcThreadAttribute(
		&pThreadAttribList,                   // Return value from InitializeProcThreadAttributeList
		0,                                    // Reserved
		PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, // Attribute - update parent process info
		&parentHandlePtr,                     // Pointer to attribute value (lpValue)
		sizeOfParentHandlePtr,                // Sizof(lpValue)
		0,                                    // Reserved
		nil,                                  // Reserved
	)
	if err != nil {
		log.Fatalf("Error updating thread attribute list: %s", err)
	}

	fmt.Printf("After Update --> pThreadAttribList: %+v\n", pThreadAttribList)

	// Only member that needs to be set is Cb to size of StartupInfoEx
	var startupInfoEx StartupInfoEx
	startupInfoEx.StartupInfo.Cb = uint32(unsafe.Sizeof(startupInfoEx))
	startupInfoEx.AttributeList = &pThreadAttribList

	// CreateProcessW
	parentProcessPathPtr, err := syscall.UTF16PtrFromString(*payload)
	if err != nil {
		log.Fatalf("Error converting parent process path: %s", err)
	}

	procInfo := windows.ProcessInformation{}

	/* The EXTENDED_STARTUPINFO_PRESENT flag gives further control over the created
	proces. It allows some information about the process to be modified such as the
	PPID */
	err = CreateProcess(
		nil,
		parentProcessPathPtr,
		nil,
		nil,
		false,
		windows.EXTENDED_STARTUPINFO_PRESENT,
		nil,
		nil,
		&startupInfoEx,
		&procInfo,
	)
	if err != nil {
		log.Fatalf("Error creating process: %s", err)
	}

	fmt.Printf("Process created successfully!\n")
	fmt.Printf("Process Info: %+v\n", procInfo)

	// Wait for user input
	var input string
	fmt.Println("Press enter to exit...")
	fmt.Scanln(&input)
}

const PROCESS_ALL_ACCESS = windows.STANDARD_RIGHTS_REQUIRED | windows.SYNCHRONIZE | 0xFFFF

// Opens a handle to a process given its PID.
func OpenHandle(pid int) (handle syscall.Handle, err error) {
	handle, err = syscall.OpenProcess(PROCESS_ALL_ACCESS, false, uint32(pid))
	if err != nil {
		return handle, err
	}

	return handle, err
}
