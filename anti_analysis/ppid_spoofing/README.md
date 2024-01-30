# PPID Spoofing

- Parent PID spoofing using direct system calls

# Guide

1. Identify a target PID to become the 'parent' of the process we'll be creating. It must be the main thread PID associated with a process.
2. Choose a target payload

```go
payload := flag.String("payload", "C:\\Program Files (x86)\\Jagex Launcher\\JagexLauncher.exe", "Parent argument")
```

3. Open a `handle` to the process, note that `PROCESS_QUERY_INFORMATION` permissions is not sufficient. It worked with `PROCESS_ALL_ACCESS` though. 

```go
const PROCESS_ALL_ACCESS = windows.STANDARD_RIGHTS_REQUIRED | windows.SYNCHRONIZE | 0xFFFF
```

4. Call the `InitialiseProcThreadAttributeList` function with a `null` `lpAttributeList` parameter - this will populate the size of `lpSize` with the size required to hold the data structure. It's intended that this function be called twice, once to get the data structure, and again to populate it. You can ignore the error on the first call. 

```go
var lpSize uintptr = 0
InitializeProcThreadAttributeList(nil, 1, 0, &lpSize)
```

There was some suggestion that you might need to allocate a byte array based on the response of lpSize because Golang's struct might not be aligned like WIN32 API expects but it doesn't seem to make any different?

```go
// attribListBytes := make([]byte, lpSize)
// pThreadAttribList := (*PROC_THREAD_ATTRIBUTE_LIST)(unsafe.Pointer(&attribListBytes[0]))
```

5. Initialise a `PROC_THREAD_ATTRIBUTE_LIST` struct

```go
// type PROC_THREAD_ATTRIBUTE_LIST struct {
//     dwFlags  uint32
//     size     uint64
//     count    uint64
//     reserved uint64
//     unknown  *uint64
//     entries  []*PROC_THREAD_ATTRIBUTE_ENTRY
// }
var pThreadAttribList PROC_THREAD_ATTRIBUTE_LIST
```

6. Call the `InitialiseProcThreadAttributeList` func agian to popular the attrib list

```go
err = InitializeProcThreadAttributeList(&pThreadAttribList, 1, 0, &lpSize)
```

7. To populate the structure fully, we need to call `UpdateProcThreadAttribute`:

```go
var parentHandlePtr uintptr = uintptr(parentHandle)
var sizeOfParentHandlePtr uintptr = unsafe.Sizeof(&parentHandlePtr)

// Update individual parameters - in this case, the parent procese (PPID)
err = UpdateProcThreadAttribute(
    &pThreadAttribList,                   // Return value from InitializeProcThreadAttributeList
    0,                                    // Reserved
    PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, // Attribute - update parent process info
    &parentHandlePtr,                     // Pointer to attribute value (lpValue)
    sizeOfParentHandlePtr,                // Sizof(lpValue)
    0,                                    // Reserved
    nil,                                  // Reserved
)
```

The `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` field specifies that we're updating the PPID.

8. Pack it all into the `startupInfoEx` structure:

```go
var startupInfoEx StartupInfoEx
startupInfoEx.StartupInfo.Cb = uint32(unsafe.Sizeof(startupInfoEx))
startupInfoEx.AttributeList = &pThreadAttribList

// CreateProcessW
parentProcessPathPtr, err := syscall.UTF16PtrFromString(*payload)
```

9. Finally, create a new process passing it the newly packed struct:

```go
procInfo := windows.ProcessInformation{}

/* The EXTENDED_STARTUPINFO_PRESENT flag gives further control over the created
proces. It allows some information about the process to be modified such as the
PPID */
err = CreateProcess(
    nil,
    parentProcessPathPtr,
    nil,
    nil,
    false,
    windows.EXTENDED_STARTUPINFO_PRESENT,
    nil,
    nil,
    &startupInfoEx,
    &procInfo,
)
```
