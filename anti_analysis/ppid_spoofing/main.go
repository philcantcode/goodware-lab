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
	payload := flag.String("payload", "C:\\code\\mal-lab\\payloads\\benign_go_exe\\benign_go.exe", "Parent argument")
	parentPPID := flag.Int("parent-ppid", 0, "Parent process PID")
	flag.Parse()

	fmt.Printf("Process To Create: %s\n", payload)

	parentHandle, err := OpenHandle(*parentPPID)
	if err != nil {
		log.Fatalf("Error opening handle to parent process: %s", err)
	}
	defer syscall.CloseHandle(parentHandle)
	fmt.Printf("Parent Handle: %d\n", parentHandle)

	var lpSize uintptr = 0
	threadAttribList := PROC_THREAD_ATTRIBUTE_LIST{}
	InitializeProcThreadAttributeList(nil, 1, 0, &lpSize)
	// threadAttribList = (*PROC_THREAD_ATTRIBUTE_LIST)(unsafe.Pointer(windows.VirtualAlloc(0, lpSize, windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)))

	InitializeProcThreadAttributeList(&threadAttribList, 1, 0, &lpSize)

	var parentHandlePtr uintptr = uintptr(parentHandle)

	UpdateProcThreadAttribute(
		&threadAttribList,
		0,
		PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
		&parentHandlePtr,
		uintptr(unsafe.Sizeof(parentHandle)),
		0,
		nil,
	)

	fmt.Printf("sThreadAttList: %+v\n", threadAttribList)

	startupInfoEx := StartupInfoEx{
		StartupInfo: windows.StartupInfo{
			Cb: uint32(unsafe.Sizeof(StartupInfoEx{})),
		},
		AttributeList: &threadAttribList,
	}

	// CreateProcessW
	parentProcessPathPtr, err := syscall.UTF16PtrFromString(*payload)
	if err != nil {
		log.Fatalf("Error converting parent process path: %s", err)
	}

	procInfo := windows.ProcessInformation{}

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
}

// Opens a handle to a process given its PID.
func OpenHandle(pid int) (handle syscall.Handle, err error) {
	handle, err = syscall.OpenProcess(syscall.PROCESS_QUERY_INFORMATION, false, uint32(pid))
	if err != nil {
		return handle, err
	}

	return handle, err
}
