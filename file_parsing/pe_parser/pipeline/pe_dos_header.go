package pipeline

import (
	"encoding/binary"
	"log"
)

type IMAGE_DOS_HEADER struct {
	E_magic    uint16     // Magic number
	E_cblp     uint16     // Bytes on last page of file
	E_cp       uint16     // Pages in file
	E_crlc     uint16     // Relocations
	E_cparhdr  uint16     // Size of header in paragraphs
	E_minalloc uint16     // Minimum extra paragraphs needed
	E_maxalloc uint16     // Maximum extra paragraphs needed
	E_ss       uint16     // Initial (relative) SS value
	E_sp       uint16     // Initial SP value
	E_csum     uint16     // Checksum
	E_ip       uint16     // Initial IP value
	E_cs       uint16     // Initial (relative) CS value
	E_lfarlc   uint16     // File address of relocation table
	E_ovno     uint16     // Overlay number
	E_res      [4]uint16  // Reserved words
	E_oemid    uint16     // OEM identifier (for e_oeminfo)
	E_oeminfo  uint16     // OEM information; e_oemid specific
	E_res2     [10]uint16 // Reserved words
	E_lfanew   int32      // File address of new exe header
}

func dosHeader(pj *ParsingJob) error {
	var dosHeader IMAGE_DOS_HEADER

	// Read the DOS header
	err := binary.Read(pj.Reader, binary.LittleEndian, &dosHeader)
	if err != nil {
		log.Printf("Error reading DOS header: %v", err)
		return err
	}

	pj.DosHeader = dosHeader

	return nil
}
