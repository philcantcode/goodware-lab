# Adding windows metadata

- Install go install github.com/josephspurrier/goversioninfo/cmd/goversioninfo to the GOPATH bin
- Add versioninfo.json to the working directory 
- Add the contents to the file:

```json
{
    "FixedFileInfo": {
      "FileVersion": {
        "Major": 112,
        "Minor": 0,
        "Patch": 5615,
        "Build": 86
      },
      "ProductVersion": {
        "Major": 112,
        "Minor": 0,
        "Patch": 5615,
        "Build": 86
      },
      "FileFlagsMask": "3f",
      "FileFlags": "00",
      "FileOS": "040004",
      "FileType": "01",
      "FileSubType": "00"
    },
    "StringFileInfo": {
      "CompanyName": "Google LLC.",
      "FileDescription": "Google Chrome",
      "InternalName": "Chrome",
      "LegalCopyright": "Copyright 2023 Google LLC.",
      "OriginalFilename": "chrome.exe",
      "ProductName": "Google Chrome",
      "ProductVersion": "112.0.5615.86"
    },
    "VarFileInfo": {
      "Translation": {
        "LangID": "0409",
        "CharsetID": "04B0"
      }
    }
}
```

- Add //go:generate goversioninfo -icon=icon.ico as a comment to go file
- Run `go generate`
- Run `go build .`