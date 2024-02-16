package main

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var kernel32 = windows.NewLazySystemDLL("kernel32.dll")

var procCreateProcessW = kernel32.NewProc("CreateProcessW")
var procVirtualAllocEx = kernel32.NewProc("VirtualAllocEx")
var procWriteProcessMemory = kernel32.NewProc("WriteProcessMemory")
var procGetThreadContext = kernel32.NewProc("GetThreadContext")
var procVirtualProtectEx = kernel32.NewProc("VirtualProtectEx")
var procResumeThread = kernel32.NewProc("ResumeThread")
var procSetThreadContext = kernel32.NewProc("SetThreadContext")

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

const (
	// CONTEXT_FLAGS
	CONTEXT_AMD64           = 0x00100000
	CONTEXT_CONTROL         = (CONTEXT_AMD64 | 0x00000001)
	CONTEXT_INTEGER         = (CONTEXT_AMD64 | 0x00000002)
	CONTEXT_SEGMENTS        = (CONTEXT_AMD64 | 0x00000004)
	CONTEXT_FLOATING_POINT  = (CONTEXT_AMD64 | 0x00000008)
	CONTEXT_DEBUG_REGISTERS = (CONTEXT_AMD64 | 0x00000010)

	// Use CONTEXT_FULL for demonstration purposes.
	CONTEXT_FULL = (CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_FLOATING_POINT)
)

type XMM_SAVE_AREA32 struct{}
type NEON128 struct{}
type M128A struct{}

type THEAD_CONTEXT_64 struct {
	P1Home       uint64
	P2Home       uint64
	P3Home       uint64
	P4Home       uint64
	P5Home       uint64
	P6Home       uint64
	ContextFlags uint32
	MxCsr        uint32
	SegCs        uint16
	SegDs        uint16
	SegEs        uint16
	SegFs        uint16
	SegGs        uint16
	SegSs        uint16
	EFlags       uint32
	Dr0          uint64
	Dr1          uint64
	Dr2          uint64
	Dr3          uint64
	Dr6          uint64
	Dr7          uint64
	Rax          uint64
	Rcx          uint64
	Rdx          uint64
	Rbx          uint64
	Rsp          uint64
	Rbp          uint64
	Rsi          uint64
	Rdi          uint64
	R8           uint64
	R9           uint64
	R10          uint64
	R11          uint64
	R12          uint64
	R13          uint64
	R14          uint64
	R15          uint64
	Rip          uint64
	// Placeholder for the union; actual implementation depends on specific needs.
	DUMMYUNIONNAME       [26]M128A // Simplified representation of the union
	VectorRegister       [26]M128A
	VectorControl        uint64
	DebugControl         uint64
	LastBranchToRip      uint64
	LastBranchFromRip    uint64
	LastExceptionToRip   uint64
	LastExceptionFromRip uint64
}

func GetThreadContextFull(threadHandle windows.Handle, context *THEAD_CONTEXT_64) error {
	context.ContextFlags = CONTEXT_FULL
	ret, _, err := procGetThreadContext.Call(
		uintptr(threadHandle),
		uintptr(unsafe.Pointer(context)),
	)
	if ret == 0 {
		return err
	}
	return nil
}

func VirtualProtectEx(hProcess windows.Handle, lpAddress uintptr, dwSize uintptr, flNewProtect uint32, lpflOldProtect *uint32) (err error) {
	r1, _, e1 := syscall.Syscall6(procVirtualProtectEx.Addr(), 5, uintptr(hProcess), uintptr(lpAddress), uintptr(dwSize), uintptr(flNewProtect), uintptr(unsafe.Pointer(lpflOldProtect)), 0)
	if r1 == 0 {
		err = error(e1)
	}
	return
}

func ResumeThread(threadHandle windows.Handle) error {
	ret, _, err := procResumeThread.Call(uintptr(threadHandle))
	if ret == ^uintptr(0) { // Equivalent to DWORD(-1)
		return fmt.Errorf("ResumeThread failed: %v", err)
	}
	return nil
}

func SetThreadContext(threadHandle windows.Handle, context *THEAD_CONTEXT_64) error {
	ret, _, err := procSetThreadContext.Call(
		uintptr(threadHandle),
		uintptr(unsafe.Pointer(context)),
	)
	if ret == 0 {
		return err
	}
	return nil
}
