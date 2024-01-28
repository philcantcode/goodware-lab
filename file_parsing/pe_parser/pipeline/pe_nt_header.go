package pipeline

import (
	"encoding/binary"
	"log"
)

type NT_HEADER struct {
	Signature      uint32
	FileHeader     IMAGE_FILE_HEADER
	OptionalHeader IMAGE_OPTIONAL_HEADER_64
}

// IMAGE_FILE_HEADER represents the file header of an executable file.
// Same for 32 and 64 bit.
type IMAGE_FILE_HEADER struct {
	Machine              uint16 // Architecture type
	NumberOfSections     uint16 // Number of sections
	TimeDateStamp        uint32 // Time and date stamp
	PointerToSymbolTable uint32 // File offset of symbol table
	NumberOfSymbols      uint32 // Number of symbols
	SizeOfOptionalHeader uint16 // Size of optional header
	Characteristics      uint16 // File characteristics
}

// IMAGE_OPTIONAL_HEADER_64 represents the optional header of an executable file.
// Different for 32 and 64 bit.
type IMAGE_OPTIONAL_HEADER_64 struct {
	Magic                       uint16 // Magic number
	MajorLinkerVersion          uint8  // Linker major version number
	MinorLinkerVersion          uint8  // Linker minor version number
	SizeOfCode                  uint32 // Size of code section
	SizeOfInitializedData       uint32 // Size of initialized data section
	SizeOfUninitializedData     uint32 // Size of uninitialized data section
	AddressOfEntryPoint         uint32 // Address of entry point
	BaseOfCode                  uint32 // Base address of code section
	ImageBase                   uint64 // Base address of image
	SectionAlignment            uint32 // Section alignment value
	FileAlignment               uint32 // File alignment value
	MajorOperatingSystemVersion uint16 // Major operating system version number
	MinorOperatingSystemVersion uint16 // Minor operating system version number
	MajorImageVersion           uint16 // Major image version number
	MinorImageVersion           uint16 // Minor image version number
	MajorSubsystemVersion       uint16 // Major subsystem version number
	MinorSubsystemVersion       uint16 // Minor subsystem version number
	Win32VersionValue           uint32 // Win32 version value
	SizeOfImage                 uint32 // Size of image
	SizeOfHeaders               uint32 // Size of headers
	CheckSum                    uint32 // Checksum
	Subsystem                   uint16 // Subsystem
	DllCharacteristics          uint16 // DLL characteristics
	SizeOfStackReserve          uint64 // Size of stack reserve
	SizeOfStackCommit           uint64 // Size of stack commit
	SizeOfHeapReserve           uint64 // Size of heap reserve
	SizeOfHeapCommit            uint64 // Size of heap commit
	LoaderFlags                 uint32 // Loader flags
	NumberOfRvaAndSizes         uint32 // Number of data-directory entries
}

type IMAGE_DATA_DIRECTORY struct {
	VirtualAddress uint32
	Size           uint32
}

func ntHeader(pj *ParsingJob) error {
	var ntHeader NT_HEADER

	// Seek to the PE header
	pj.Reader.Seek(int64(pj.DosHeader.E_lfanew), 0)

	// Read the NT header
	err := binary.Read(pj.Reader, binary.LittleEndian, &ntHeader)
	if err != nil {
		log.Printf("Error reading PE header: %v", err)
		return err
	}

	pj.NtHeader = ntHeader

	return nil
}

func dataDirectories(pj *ParsingJob) error {
	var dataDirectories []IMAGE_DATA_DIRECTORY

	// Read the data directories
	numDataDirectories := pj.NtHeader.OptionalHeader.NumberOfRvaAndSizes
	dataDirectories = make([]IMAGE_DATA_DIRECTORY, numDataDirectories)
	err := binary.Read(pj.Reader, binary.LittleEndian, &dataDirectories)
	if err != nil {
		log.Printf("Error reading data directories: %v", err)
		return err
	}

	pj.DataDirectories = dataDirectories

	return nil
}
