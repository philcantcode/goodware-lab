# PE File

In a Portable Executable (PE) file format, which is used in Windows operating systems for executable files, DLLs, and others, the data directories are indeed located within the NT (New Technology) header.

The NT header is a critical part of the PE file structure and is composed of two primary sections:

File Header: This part contains general information about the file, such as its type (executable, DLL, etc.), timestamp, size of optional header, and more.

Optional Header: Despite its name, this header is mandatory for executable files. It contains more specific information about the executable, such as the entry point address, the image base, and the data directories.

The data directories are an array within the Optional Header. They provide information to locate and size several important data structures within the PE file, such as:

Export Table
Import Table
Resource Table
Exception Table
Certificate Table
Base Relocation Table
Debugging Information
Thread Local Storage (TLS) Table
Load Configuration Table
Bound Import Table
Import Address Table
Delay Import Descriptor
CLR Runtime Header

Each entry in the array of data directories gives the Relative Virtual Address (RVA) and size of one of these tables or structures if they exist in the PE file. This organization allows the Windows loader and other tools to find and process these structures efficiently when loading or analyzing the PE file.