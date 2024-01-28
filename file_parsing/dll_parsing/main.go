package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"syscall"
)

const DLL_PATH = "../../payloads/calc_exe/calc.dll"

func main() {
	dll, err := syscall.LoadDLL(DLL_PATH)
	defer dll.Release()
	if err != nil {
		log.Fatalf("Error loading DLL: %v", err)
	}

	dllFileSize := getFileSize(DLL_PATH)
	dllBytes := readFileBytes(DLL_PATH)
	dosHeader, fileHeader, err := parsePE(dllBytes)

	fmt.Printf("DLL File Size: %d\n", dllFileSize)
	fmt.Printf("DLL DOS Header: %+v\n", dosHeader)
	fmt.Printf("DLL File Header: %+v\n", fileHeader)

}

// Parses the PE header into various structs
func parsePE(inputBytes []byte) (IMAGE_DOS_HEADER, IMAGE_FILE_HEADER, error) {
	reader := bytes.NewReader(inputBytes)

	var dosHeader IMAGE_DOS_HEADER
	var fileHeader IMAGE_FILE_HEADER

	// Read the DOS header
	err := binary.Read(reader, binary.LittleEndian, &dosHeader)
	if err != nil {
		return dosHeader, fileHeader, err
	}

	// Read the file header
	err = binary.Read(reader, binary.LittleEndian, &fileHeader)
	if err != nil {
		return dosHeader, fileHeader, err
	}

	return dosHeader, fileHeader, nil
}

func readFileBytes(filePath string) []byte {
	// Open the file
	file, err := os.Open(filePath)
	if err != nil {
		log.Fatalf("Error opening file: %v", err)
	}
	defer file.Close()

	// Get file stats
	fileInfo, err := file.Stat()
	if err != nil {
		log.Fatalf("Error getting file stats: %v", err)
	}

	// Size of the file
	fileSize := fileInfo.Size() // Size in bytes

	// Read the file into a byte array
	fileBytes := make([]byte, fileSize)
	bytesRead, err := file.Read(fileBytes)
	if err != nil {
		log.Fatalf("Error reading file: %v", err)
	}

	fmt.Printf("Bytes read: %d\n", bytesRead)

	return fileBytes
}

// Get the size of the DLL
func getFileSize(filePath string) int64 {
	file, err := os.Open(filePath)
	if err != nil {
		log.Fatalf("Error opening file: %v", err)
	}
	defer file.Close()

	// Get file stats
	fileInfo, err := file.Stat()
	if err != nil {
		log.Fatalf("Error getting file stats: %v", err)
	}

	// Size of the file
	fileSize := fileInfo.Size() // Size in bytes

	return fileSize
}
