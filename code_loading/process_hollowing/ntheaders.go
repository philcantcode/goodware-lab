package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
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

func getPeNtHeaders64(peContents []byte) (*NT_HEADER, error) {
	if len(peContents) < 0x40 {
		return nil, errors.New("PE contents too short")
	}

	// Read the e_lfanew field to find the PE header offset
	e_lfanewOffset := int(binary.LittleEndian.Uint32(peContents[0x3C:0x40]))
	if len(peContents) < e_lfanewOffset+4 {
		return nil, errors.New("Invalid e_lfanew offset")
	}

	// Ensure the PE signature is correct
	if string(peContents[e_lfanewOffset:e_lfanewOffset+4]) != "PE\x00\x00" {
		return nil, errors.New("Invalid PE signature")
	}

	// Setup a reader starting at the COFF File Header
	reader := bytes.NewReader(peContents[e_lfanewOffset+4:])

	var ntHeaders NT_HEADER
	// Read the FileHeader
	if err := binary.Read(reader, binary.LittleEndian, &ntHeaders.FileHeader); err != nil {
		return nil, err
	}

	// Optional Header starts immediately after FileHeader; check for PE32+ magic
	var magic uint16
	if err := binary.Read(reader, binary.LittleEndian, &magic); err != nil {
		return nil, err
	}
	if magic != 0x20B {
		return nil, errors.New("Not a PE32+ file")
	}

	// Move the reader back to the start of the OptionalHeader (including magic)
	reader.Seek(-2, io.SeekCurrent)

	// Read the OptionalHeader
	if err := binary.Read(reader, binary.LittleEndian, &ntHeaders.OptionalHeader); err != nil {
		return nil, err
	}

	return &ntHeaders, nil
}
