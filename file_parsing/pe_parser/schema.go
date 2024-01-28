package main

// IMAGE_DOS_HEADER represents the DOS header of an executable file.
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

type NT_HEADER struct {
	Signature      uint32
	FileHeader     IMAGE_FILE_HEADER
	OptionalHeader IMAGE_OPTIONAL_HEADER_64
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

type IMAGE_DATA_DIRECTORY struct {
	VirtualAddress uint32
	Size           uint32
}

// Exports
// Same for 32 and 64 bit.
type IMAGE_EXPORT_DIRECTORY struct {
	Characteristics       uint32
	TimeDateStamp         uint32
	MajorVersion          uint16
	MinorVersion          uint16
	Name                  uint32
	Base                  uint32
	NumberOfFunctions     uint32
	NumberOfNames         uint32
	AddressOfFunctions    uint32
	AddressOfNames        uint32
	AddressOfNameOrdinals uint32
}

// Imports
// Same for 32 and 64 bit.
type IMAGE_IMPORT_DESCRIPTOR struct {
	OriginalFirstThunk uint32
	TimeDateStamp      uint32
	ForwarderChain     uint32
	Name               uint32
	FirstThunk         uint32
}
