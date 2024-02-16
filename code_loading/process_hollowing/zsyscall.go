package main

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var kernel32 = windows.NewLazySystemDLL("kernel32.dll")

var procCreateProcessW = kernel32.NewProc("CreateProcessW")
var procVirtualAllocEx = kernel32.NewProc("VirtualAllocEx")
var procWriteProcessMemory = kernel32.NewProc("WriteProcessMemory")

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

func CreateProcess(appName *uint16, commandLine *uint16, procSecurity *windows.SecurityAttributes, threadSecurity *windows.SecurityAttributes, inheritHandles bool, creationFlags uint32, env *uint16, currentDir *uint16, startupInfo *StartupInfoEx, outProcInfo *windows.ProcessInformation) (err error) {
	var _p0 uint32
	if inheritHandles {
		_p0 = 1
	}
	r1, _, e1 := syscall.Syscall12(
		procCreateProcessW.Addr(),
		10,
		uintptr(unsafe.Pointer(appName)),
		uintptr(unsafe.Pointer(commandLine)),
		uintptr(unsafe.Pointer(procSecurity)),
		uintptr(unsafe.Pointer(threadSecurity)),
		uintptr(_p0), uintptr(creationFlags),
		uintptr(unsafe.Pointer(env)),
		uintptr(unsafe.Pointer(currentDir)),
		uintptr(unsafe.Pointer(startupInfo)),
		uintptr(unsafe.Pointer(outProcInfo)),
		0,
		0,
	)
	if r1 == 0 {
		err = error(e1)
	}
	return
}

func VirtualAllocEx(hProcess windows.Handle, lpAddress uintptr, dwSize uintptr, flAllocationType uint32, flProtect uint32) (addr uintptr, err error) {
	r0, _, e1 := syscall.Syscall6(procVirtualAllocEx.Addr(), 5, uintptr(hProcess), uintptr(lpAddress), uintptr(dwSize), uintptr(flAllocationType), uintptr(flProtect), 0)
	addr = uintptr(r0)
	if addr == 0 {
		err = error(e1)
	}
	return
}

// Writes data to an area of memory in a specified process. The entire area to be written to must be accessible or the operation fails.
func WriteProcessMemory(hProcess windows.Handle, lpBaseAddress uintptr, lpBuffer *byte, nSize uintptr, lpNumberOfBytesWritten *uintptr) (err error) {
	r1, _, e1 := syscall.Syscall6(procWriteProcessMemory.Addr(), 5, uintptr(hProcess), uintptr(lpBaseAddress), uintptr(unsafe.Pointer(lpBuffer)), uintptr(nSize), uintptr(unsafe.Pointer(lpNumberOfBytesWritten)), 0)
	if r1 == 0 {
		err = error(e1)
	}
	return
}
