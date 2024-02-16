package pipeline

import (
	"log"
	"os"
)

func readFileBytes(filePath string) ([]byte, error) {
	// Open the file
	file, err := os.Open(filePath)
	if err != nil {
		log.Printf("Error opening file: %v", err)
		return nil, err
	}
	defer file.Close()

	// Get file stats
	fileInfo, err := file.Stat()
	if err != nil {
		log.Printf("Error getting file stats: %v", err)
		return nil, err
	}

	// Size of the file
	fileSize := fileInfo.Size() // Size in bytes

	// Read the file into a byte array
	fileBytes := make([]byte, fileSize)
	_, err = file.Read(fileBytes)
	if err != nil {
		log.Printf("Error reading file: %v", err)
		return nil, err
	}

	return fileBytes, nil
}

func convertRvaToFileOffset(rva uint32, sectionHeaders []IMAGE_SECTION_HEADER) (uint32, error) {
	for _, section := range sectionHeaders {
		if rva >= section.VirtualAddress && rva < section.VirtualAddress+section.VirtualSize {
			fileOffset := rva - section.VirtualAddress + section.PointerToRawData
			return fileOffset, nil
		}
	}

	return 0, nil
}
