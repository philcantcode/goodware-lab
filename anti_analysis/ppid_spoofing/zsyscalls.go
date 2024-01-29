package main

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

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
		err = errnoErr(e1)
	}
	return
}

func InitializeProcThreadAttributeList(lpAttributeList *PROC_THREAD_ATTRIBUTE_LIST, dwAttributeCount uint32, dwFlags uint32, lpSize *uintptr) (err error) {
	r1, _, e1 := syscall.Syscall6(procInitializeProcThreadAttributeList.Addr(), 4, uintptr(unsafe.Pointer(lpAttributeList)), uintptr(dwAttributeCount), uintptr(dwFlags), uintptr(unsafe.Pointer(lpSize)), 0, 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func UpdateProcThreadAttribute(lpAttributeList *PROC_THREAD_ATTRIBUTE_LIST, dwFlags uint32, attribute uintptr, lpValue *uintptr, cbSize uintptr, lpPreviousValue uintptr, lpReturnSize *uintptr) (err error) {
	r1, _, e1 := syscall.Syscall9(procUpdateProcThreadAttribute.Addr(), 7, uintptr(unsafe.Pointer(lpAttributeList)), uintptr(dwFlags), uintptr(attribute), uintptr(unsafe.Pointer(lpValue)), uintptr(cbSize), uintptr(lpPreviousValue), uintptr(unsafe.Pointer(lpReturnSize)), 0, 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

// errnoErr returns common boxed Errno values, to prevent
// allocations at runtime.
func errnoErr(e syscall.Errno) error {
	switch e {
	case 0:
		return errERROR_EINVAL
	case errnoERROR_IO_PENDING:
		return errERROR_IO_PENDING
	}
	// TODO: add more here, after collecting data on the common
	// error values see on Windows. (perhaps when running
	// all.bat?)
	return e
}
