package main

import (
	"fmt"
	"log"

	"github.com/philcantcode/mal-lab/file_parsing/pe_parser/pipeline"
)

const DLL_PATH = "../../payloads/calc_exe/calc.dll"

func main() {
	pe, err := pipeline.ParsePEx64(DLL_PATH)
	if err != nil {
		log.Fatalf("Error parsing PE: %v", err)
	}

	fmt.Printf("Imports: %+v\n", pe.ImportFuncNames)
}
