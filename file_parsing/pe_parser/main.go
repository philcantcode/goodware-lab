package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/philcantcode/mal-lab/file_parsing/pe_parser/pipeline"
)

func main() {
	peFile := flag.String("pe-file", "../../payloads/calc_exe/calc.dll", "Path to the PE file")
	display := flag.String("display", "all", "Field to display: imports, exports, all")

	flag.Parse()

	pe, err := pipeline.ParsePEx64(*peFile)
	if err != nil {
		log.Fatalf("Error parsing PE: %v", err)
	}

	switch *display {
	case "imports":
		displayNumberedArray(pe.ImportFuncNames)
	case "exports":
		displayNumberedArray(pe.ExportFuncNames)
	case "all":
		fmt.Printf("%+v\n", pe.ImportFuncNames)
	default:
		fmt.Println("Invalid display field")
	}
}

func displayNumberedArray(arr []string) {
	for i, s := range arr {
		fmt.Printf("%d. %s\n", i+1, s)
	}
}
