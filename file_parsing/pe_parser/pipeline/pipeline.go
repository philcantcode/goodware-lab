package pipeline

import (
	"bytes"
	"log"
	"reflect"
	"runtime"
)

type FileUnpacker func(*ParsingJob) error

type ParsingJob struct {
	File   string
	Bytes  []byte
	Reader *bytes.Reader

	DosHeader       IMAGE_DOS_HEADER
	NtHeader        NT_HEADER
	DataDirectories []IMAGE_DATA_DIRECTORY
	SectionHeaders  []IMAGE_SECTION_HEADER

	Exports         IMAGE_EXPORT_DIRECTORY
	ExportFuncNames []string

	Imports         []IMAGE_IMPORT_DESCRIPTOR
	ImportFuncNames []string
}

func initialisePipeline(funcs ...FileUnpacker) FileUnpacker {
	return func(pm *ParsingJob) error {
		for _, fn := range funcs {
			err := fn(pm)
			if err != nil {
				// Reflect the name of the function
				funcName := runtime.FuncForPC(reflect.ValueOf(fn).Pointer()).Name()
				log.Printf("Pipeline function %s returned error: %v", funcName, err)

				return err
			}
		}
		return nil
	}
}

func ParsePEx64(path string) (*ParsingJob, error) {
	pipeline := initialisePipeline(
		initialise,
		dosHeader,
		ntHeader,
		dataDirectories,
		sectionHeaders,
		exportTable,
		exportFunctionNames,
		importTable,
		importFunctionNames64,
	)

	pj := &ParsingJob{
		File: path,
	}

	err := pipeline(pj)

	return pj, err
}

// The first step in the pipeline is to read the file into a byte array
func initialise(pj *ParsingJob) error {
	fileBytes, err := readFileBytes(pj.File)
	if err != nil {
		return err
	}
	pj.Bytes = fileBytes
	pj.Reader = bytes.NewReader(pj.Bytes)

	return nil
}
