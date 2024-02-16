package pipeline

import (
	"encoding/binary"
	"fmt"
	"log"
)

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

type IMAGE_IMPORT_DESCRIPTOR struct {
	OriginalFirstThunk uint32
	TimeDateStamp      uint32
	ForwarderChain     uint32
	Name               uint32
	FirstThunk         uint32
}

// IMAGE_THUNK_DATA represents an entry in an array of imports.
// The PE specification uses a union here, which can represent an address, an ordinal, or an RVA.
// The actual interpretation depends on the context and the highest bit value.
type IMAGE_THUNK_DATA64 struct {
	U1 uint64
}

func (itd *IMAGE_THUNK_DATA64) IsOrdinal() bool {
	// In PE32+, if the highest bit is set, the rest of the value is treated as an ordinal.
	return itd.U1&0x8000000000000000 != 0
}

func (itd *IMAGE_THUNK_DATA64) Ordinal() uint16 {
	// The ordinal is in the lower 16 bits of the value.
	return uint16(itd.U1 & 0xffff)
}

func (itd *IMAGE_THUNK_DATA64) AddressOfData() uint64 {
	// Mask the highest bit to get the address.
	return itd.U1 & 0x7fffffffffffffff
}

func exportTable(pj *ParsingJob) error {
	// Get the address of the export table from the first entry in the data directories
	exportTableAddress := pj.DataDirectories[0].VirtualAddress
	exportTableOffset := pj.DataDirectories[0].VirtualAddress

	// Ensure that the export table address is valid
	if exportTableAddress == 0 {
		log.Printf("No export table present")
		return nil
	}

	// Convert the RVA to file offset here (this code is not included, as it depends on the specifics of your implementation)
	exportTableOffset, err := convertRvaToFileOffset(exportTableAddress, pj.SectionHeaders)
	if err != nil {
		return err
	}

	// Seek to the position of the export table in the file
	_, err = pj.Reader.Seek(int64(exportTableOffset), 0) // Use the correct file offset instead of the RVA
	if err != nil {
		return err
	}

	// Read the export table
	var exportTable IMAGE_EXPORT_DIRECTORY
	err = binary.Read(pj.Reader, binary.LittleEndian, &exportTable)
	if err != nil {
		return err
	}

	pj.Exports = exportTable

	return nil
}

func exportFunctionNames(pj *ParsingJob) error {
	namesRVA := pj.Exports.AddressOfNames
	namesOffset, err := convertRvaToFileOffset(namesRVA, pj.SectionHeaders)
	if err != nil {
		return err
	}

	// Seek to the position of the names table in the file
	_, err = pj.Reader.Seek(int64(namesOffset), 0) // Use the correct file offset instead of the RVA
	if err != nil {
		return err
	}

	// Read the names table
	var names []uint32
	for i := 0; i < int(pj.Exports.NumberOfNames); i++ {
		var name uint32
		err = binary.Read(pj.Reader, binary.LittleEndian, &name)
		if err != nil {
			return err
		}
		names = append(names, name)
	}

	exportNames := []string{}
	// Read the names
	for _, nameRva := range names {
		nameOffset, err := convertRvaToFileOffset(nameRva, pj.SectionHeaders)
		if err != nil {
			return err
		}

		_, err = pj.Reader.Seek(int64(nameOffset), 0)
		if err != nil {
			return err
		}

		var nameBytes []byte
		var ch byte
		for {
			err = binary.Read(pj.Reader, binary.LittleEndian, &ch)
			if err != nil || ch == 0 {
				break
			}

			nameBytes = append(nameBytes, ch)
		}

		exportNames = append(exportNames, string(nameBytes))
	}

	pj.ExportFuncNames = exportNames

	return nil
}

// Imports
func importTable(pj *ParsingJob) error {
	// Get the address of the import table from the second entry in the data directories
	importTableAddress := pj.DataDirectories[1].VirtualAddress

	// Ensure that the import table address is valid
	if importTableAddress == 0 {
		log.Printf("No import table present")
		return nil
	}

	// Convert the RVA to file offset
	importTableOffset, err := convertRvaToFileOffset(importTableAddress, pj.SectionHeaders)
	if err != nil {
		return err
	}

	// Seek to the position of the import table in the file
	_, err = pj.Reader.Seek(int64(importTableOffset), 0)
	if err != nil {
		return err
	}

	imports := []IMAGE_IMPORT_DESCRIPTOR{}

	// Read the import table in a loop
	for {
		var importDescriptor IMAGE_IMPORT_DESCRIPTOR
		err = binary.Read(pj.Reader, binary.LittleEndian, &importDescriptor)
		if err != nil {
			return err
		}

		// Check for an all-zeroes descriptor, indicating the end of the import table
		if importDescriptor.OriginalFirstThunk == 0 &&
			importDescriptor.TimeDateStamp == 0 &&
			importDescriptor.ForwarderChain == 0 &&
			importDescriptor.Name == 0 &&
			importDescriptor.FirstThunk == 0 {
			break
		}

		imports = append(imports, importDescriptor)
	}

	pj.Imports = imports

	return nil
}

func importFunctionNames64(pj *ParsingJob) error {
	var importNames []string

	for _, descriptor := range pj.Imports {
		thunkRVA := descriptor.FirstThunk
		for {
			thunkOffset, err := convertRvaToFileOffset(thunkRVA, pj.SectionHeaders)
			if err != nil {
				fmt.Println("Error converting RVA to file offset:", err)
				return err
			}

			_, err = pj.Reader.Seek(int64(thunkOffset), 0)
			if err != nil {
				fmt.Println("Error seeking to file offset:", err)
				return err
			}

			var thunkData IMAGE_THUNK_DATA64
			err = binary.Read(pj.Reader, binary.LittleEndian, &thunkData)
			if err != nil {
				fmt.Println("Error reading thunk data:", err)
				return err
			}

			if thunkData.U1 == 0 {
				break
			}

			if !thunkData.IsOrdinal() {
				nameOffset, err := convertRvaToFileOffset(uint32(thunkData.AddressOfData()), pj.SectionHeaders)
				if err != nil {
					fmt.Println("Error converting name RVA to file offset:", err)
					return err
				}

				// Skip the hint
				_, err = pj.Reader.Seek(int64(nameOffset+2), 0)
				if err != nil {
					fmt.Println("Error seeking to name offset:", err)
					return err
				}

				var nameBytes []byte
				var ch byte
				for {
					err = binary.Read(pj.Reader, binary.LittleEndian, &ch)
					if err != nil || ch == 0 {
						break
					}

					nameBytes = append(nameBytes, ch)
				}

				name := string(nameBytes)
				importNames = append(importNames, name)
			}

			thunkRVA += uint32(binary.Size(thunkData))
		}
	}

	pj.ImportFuncNames = importNames

	return nil
}
