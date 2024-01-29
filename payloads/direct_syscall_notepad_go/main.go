package main

import (
	"fmt"
	"syscall"

	"golang.org/x/sys/windows"
)

func main() {
	appName := syscall.StringToUTF16Ptr("C:\\Windows\\System32\\notepad.exe")
	var startupInfo StartupInfoEx
	var processInfo windows.ProcessInformation

	err := CreateProcess(
		appName,      // Application Name
		nil,          // Command Line
		nil,          // Process Security Attributes
		nil,          // Thread Security Attributes
		false,        // Inherit Handles
		0,            // Creation Flags
		nil,          // Environment
		nil,          // Current Directory
		&startupInfo, // Startup Info
		&processInfo, // Process Information
	)

	if err != nil {
		fmt.Printf("CreateProcess failed: %v\n", err)
		return
	}

	defer windows.CloseHandle(processInfo.Process)
	defer windows.CloseHandle(processInfo.Thread)

	fmt.Printf("Started Notepad with Process ID %d\n", processInfo.ProcessId)
}
