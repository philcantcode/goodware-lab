package main

import (
	"syscall"
	"unsafe"
)

var (
	user32             = syscall.NewLazyDLL("user32.dll")
	messageBox         = user32.NewProc("MessageBoxW")
	mb_OK              = 0x00000000
	mb_IconInformation = 0x00000040
)

func main() {
	var (
		title  = "Message"
		text   = "Hello, world!"
		handle = uintptr(0)
	)

	messageBox.Call(
		handle,
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(text))),
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(title))),
		uintptr(mb_OK|mb_IconInformation),
	)
}
