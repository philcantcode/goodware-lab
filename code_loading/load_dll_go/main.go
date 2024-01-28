package main

import (
	"fmt"
	"syscall"
)

func main() {
	dll, err := syscall.LoadDLL("../../payloads/calc_exe/calc.dll")
	if err != nil {
		fmt.Println("Error loading DLL:", err)
		return
	}
	defer dll.Release()

	// Add more code to use the functions from the DLL as needed
}
