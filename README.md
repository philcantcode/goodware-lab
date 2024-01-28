# Golang Setup

- Every folder is a stand-alone Golang project.
- Every folder needs to be initialised with:

1. `go mod init github.com/philcantcode/mal-lab/<parent-folder>/<sub-folder>`
2. `go mod tidy`
3. In the root `go.work` add `./<parent-folder>/<sub-folder>` 

## Compiling

- Ensure that the `CGO_ENABLE` envirionrment variable is set to `1`
- Check go environment variables by typing `go env`
- Ensure that the `CC` env variable is set in the windows environment panel, point it to MinGW
- Don't compile with Cygwin as it will require Cygwin DLLs to be present on the target
- Compile with mingw GCC instead, it uses the Win32API calls instead

Ref: https://sourceforge.net/projects/mingw-w64/files/latest/download
Ref: Pre-compiled MinGW for win: https://winlibs.com/

## Golang Things

- To import `unsafe` without actually using it and prevent FMT from removing it, do `import _ "unsafe"`

# AV Detection

| Action | Description | AV Response | Mitigation |
|----------|----------|----------|----------|
| Load DLL | Loaded a DLL with calc.exe payload | None | N/A |
