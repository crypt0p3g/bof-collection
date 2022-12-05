# Various BOF collection

| Name               | Description| 
| ------------------ | ---------------------- | 
| ChromiumKeyDump    | BOF implementation of [Chlonium](https://github.com/rxwx/chlonium) tool to dump Chrome/Edge Masterkey and download Cookie/Login Data files   | 
| Sleeper            | BOF to call the SetThreadExecutionState function to prevent host from `Sleeping` | 

### How to compile:

- Visual Studio:

```
x86:
"C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars32.bat"
cl.exe /c /GS- /TP BOF.cpp /FoBOF.o

x64:
"C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars64.bat"
cl.exe /c /GS- /TP BOF.cpp /FoBOF.x64.o
```

- MinGW: 

```
x86: i686-w64-mingw32-gcc -c BOF.cpp -o BOF.o
x64: x86_64-w64-mingw32-gcc -c BOF.cpp -o BOF.x64.o
```
#### After compiling, place the object files (.o) into the bin folder and load the (.cna) files to Cobalt Strike.

## ChromiumKeyDump

### Usage:
```
chromiumkeydump [edge|chrome] [argument(required)] [ChromePath(optional)]
                Arguments       Description
                ---------       -----------
                masterkey       Dump Masterkey
                cookies         Download Chrome Cookies file
                logindata       Download Chrome Login Data file
                all             Dump Masterkey and download files
                
                ChromePath      Path to custom installation directory
                                !Set the path to where the [User Data] folder is located!

                                Example: D:\\Programs\\
                                         C:\\Users\\USER\\AppData\\Local
```
### References:
https://github.com/rxwx/chlonium



## Sleeper

### Usage:
```
sleeper [argument(required)]
               Arguments      Description
               ---------      -----------
               off            Set the `ES_CONTINUOUS` flag and return to Default state
               on             Set the `ES_SYSTEM_REQUIRED` flag to prevent the Sleep
               force          Set the `ES_SYSTEM_REQUIRED|ES_AWAYMODE_REQUIRED` flags to prevent the Sleep, 
                              even if the Sleep button is pressed
```
### References:
https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-setthreadexecutionstate
