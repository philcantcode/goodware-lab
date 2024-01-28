package main

import (
	"C"
	"os/exec"
	"syscall"
	_ "unsafe"
)

// go build -buildmode=c-shared -o calc.dll

//
//export OpenCalc
func OpenCalc() {
	cmd := exec.Command("C:\\Windows\\System32\\calc.exe")
	cmd.Start()
}

func main() {} // Required but unused

// Required to build a DLL
//
//go:linkname _DllMain syscall.DllMain
var _DllMain uintptr = syscall.NewCallback(func(hinstDLL uintptr, fdwReason uintptr, lpvReserved uintptr) uintptr {
	switch fdwReason {
	case 1: // DLL_PROCESS_ATTACH
		OpenCalc()
	case 2: // DLL_THREAD_ATTACH
		OpenCalc()
	case 3: // DLL_THREAD_DETACH
		OpenCalc()
	case 0: // DLL_PROCESS_DETACH
		OpenCalc()
	}
	return 1
})

//go:linkname _cgo_sys_thread_create runtime.cgo_sys_thread_create
//go:nosplit
func _cgo_sys_thread_create() {
	// We do not want Go to create threads for us.
}

//go:linkname _cgo_notify_runtime_init_done runtime.cgo_notify_runtime_init_done
//go:nosplit
func _cgo_notify_runtime_init_done() {
	// We do not want Go to notify us.
}

//go:linkname _cgo_setenv runtime.cgo_setenv
//go:nosplit
func _cgo_setenv() {
	// We do not want Go to set environment variables for us.
}

//go:linkname _cgo_unsetenv runtime.cgo_unsetenv
//go:nosplit
func _cgo_unsetenv() {
	// We do not want Go to unset environment variables for us.
}
