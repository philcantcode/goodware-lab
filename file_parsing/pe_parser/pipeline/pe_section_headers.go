package pipeline

import (
	"encoding/binary"
)

// IMAGE_SECTION_HEADER represents the section header of an executable file.
// Same for 32 and 64 bit.
type IMAGE_SECTION_HEADER struct {
	Name                 [8]byte // Section name
	VirtualSize          uint32  // Virtual size
	VirtualAddress       uint32  // Virtual address
	SizeOfRawData        uint32  // Size of raw data
	PointerToRawData     uint32  // File offset of raw data
	PointerToRelocations uint32  // File offset of relocation table
	PointerToLinenumbers uint32  // File offset of line-number table
	NumberOfRelocations  uint16  // Number of relocations
	NumberOfLinenumbers  uint16  // Number of line-number entries
	Characteristics      uint32  // Section characteristics
}

func sectionHeaders(pj *ParsingJob) error {
	numSections := pj.NtHeader.FileHeader.NumberOfSections
	sectionHeaders := make([]IMAGE_SECTION_HEADER, numSections)
	err := binary.Read(pj.Reader, binary.LittleEndian, &sectionHeaders)
	if err != nil {
		return err
	}

	pj.SectionHeaders = sectionHeaders

	return nil
}
