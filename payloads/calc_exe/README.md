# calc.dll

Is a DLL built in golang compiled with MinGW64. 

Pops open a calc.exe upon load.

# Build

go build -buildmode=c-shared -o calc.dll

# Important Notes

- You must import "C" even if its unused in the program.
- To export a function for use by the program using the DLL, include a comment `//export <Func Name>` on the line directly above the function definition.  
- calc.exe path must be hardcoded