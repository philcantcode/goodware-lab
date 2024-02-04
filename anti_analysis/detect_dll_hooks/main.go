package main

import (
	"crypto/sha256"
	"fmt"
	"io/ioutil"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

func main() {
	processID := windows.GetCurrentProcessId()

	// Open the process with necessary access rights
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, false, processID)
	if err != nil {
		fmt.Printf("Error opening process: %v\n", err)
		return
	}
	defer windows.CloseHandle(handle)

	// Define a slice to hold module handles, initially with an estimated size
	modules := make([]windows.Handle, 1024)
	var needed uint32

	// Enumerate loaded modules (DLLs)
	err = windows.EnumProcessModules(handle, &modules[0], uint32(len(modules)*int(unsafe.Sizeof(modules[0]))), &needed)
	if err != nil {
		fmt.Printf("Error enumerating modules: %v\n", err)
		return
	}

	moduleCount := int(needed) / int(unsafe.Sizeof(modules[0]))

	// Check if the initial slice was too small
	if moduleCount > len(modules) {
		modules = make([]windows.Handle, moduleCount)
		err = windows.EnumProcessModules(handle, &modules[0], uint32(len(modules)*int(unsafe.Sizeof(modules[0]))), &needed)
		if err != nil {
			fmt.Printf("Error re-enumerating modules with resized slice: %v\n", err)
			return
		}

		moduleCount = int(needed) / int(unsafe.Sizeof(modules[0])) // Recalculate module count
	}

	// Iterate through modules
	for i := 0; i < moduleCount; i++ {
		var moduleName [windows.MAX_PATH]uint16

		// Get module file name
		err := windows.GetModuleFileNameEx(handle, modules[i], &moduleName[0], uint32(len(moduleName)))
		if err != nil {
			fmt.Printf("Error getting module name for module %d: %v\n", i, err)
			continue
		}

		// Convert filename from UTF-16 to Go string
		moduleNameStr := syscall.UTF16ToString(moduleName[:])

		hash, err := CalculateSHA256(moduleNameStr)
		if err != nil {
			fmt.Printf("Error calculating SHA256 for module %s: %v\n", moduleNameStr, err)
			continue
		}

		fmt.Printf("Loaded Module: %s (%s)\n", moduleNameStr, byteArrToHexStr(hash))

		// Additional logic to compare the loaded module to the disk version would go here
	}
}

func CalculateSHA256(filepath string) ([]byte, error) {
	data, err := ioutil.ReadFile(filepath)
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256(data)
	return hash[:], nil
}

func byteArrToHexStr(b []byte) string {
	return fmt.Sprintf("%x", b)
}
