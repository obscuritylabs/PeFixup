# PeFixup
PE File Blessing - A PE tainting tool
- [PeFixup](#pefixup)
  * [Install PeFixup](#install-pefixup)
    + [Installl from source](#installl-from-source)
    + [Installl from PYPI (Under Dev)](#installl-from-pypi--under-dev-)
    + [Installl from DockerHub](#installl-from-dockerhub)
  * [Features](#features)
  * [Help & examples](#help---examples)
    + [Examples](#examples)
    + [Example Output](#example-output)

## Install PeFixup
### Installl from source
```bash
$ git clone https://github.com/obscuritylabs/PeFixup.git
$ cd Pefixup
$ pip3 install -r requirements.txt
$ python3 pefixup.py -h
```
**or using pipenv**
```bash
$ https://github.com/obscuritylabs/PeFixup.git
$ cd Pefixup
$ pipenv install
$ pipenv shell 
(PeFixup) bash-3.2$ 
```
### Installl from PYPI (Under Dev)
```
$ pip install --user pefixup
$ pefixup -h
```
### Installl from DockerHub
```
$ docker pull obscuritylabs/pefixup:latest
$ docker pull obscuritylabs/pefixup:0.0.1
$ docker pull obscuritylabs/pefixup:development
```

## Features
Currently we have implemented the following tainting capabilities:
* taint compile times within `IMAGE_FILE_HEADER`
* taint major & minor compiler versions within `_IMAGE_OPTIONAL_HEADER`
* taint multiple compile times within `DIRECTORY_ENTRY_DEBUG`
* taint multiple pdb headers within `DIRECTORY_ENTRY_DEBUG & CV_INFO_PDB70`

Currently we have implemented the following metadata capabilities:
* Hashing
    * MD5
    * SHA1 
    * SHA256
    * SHA512
    * imphash
    * ssdeep
* Imports
    * All binary imports within `DIRECTORY_ENTRY_IMPORT`
    * All binary import function name & addr
    * Import function name checks to alert on potentially dangerous imports (AV/Analysis)
* Binary metadata
    * PE header data
    * Binary Magic values
    * EXIF data
* Runtime Checks
    * pre-flight checks 
    * sanity checks
    * post-flight checks
    * burnt checks
* Burnt checks
    * providers
        * VirusTotal (Checks Hash ONLY)
    * binary sections (dynamic sections)
        * non-cooked payload
        * cooked payload
        * .text
        * .rdata
        * .data
        * .pdata
        * .tls
        * .rsrc

## Help & examples 

```bash
$ python3 pefixup.py --help


    -------------------------------
    █▀▀█ █▀▀ █▀▀ ░▀░ █░█ █░░█ █▀▀█
    █░░█ █▀▀ █▀▀ ▀█▀ ▄▀▄ █░░█ █░░█
    █▀▀▀ ▀▀▀ ▀░░ ▀▀▀ ▀░▀ ░▀▀▀ █▀▀▀
    -------------------------------                                                                                           
    
usage: pefixup.py [-h] [-c COMPILE_TIME] [-p PDB] [-ma MAJOR_LINKER_VERSION]
                  [-mi MINOR_LINKER_VERSION] [-o OUTPUT] [-json JSON] [-s]
                  [-vt VT_API_KEY] [-v] [-d]
                  INPUT LIVE

positional arguments:
  INPUT                 input file to process
  LIVE                  output file name

optional arguments:
  -h, --help            show this help message and exit
  -c COMPILE_TIME, --compile-time COMPILE_TIME
                        Cooked payload epoc compile time to taint
  -p PDB, --pdb PDB     Cooked payload PDB (Ex. fun)
  -ma MAJOR_LINKER_VERSION, --major-linker-version MAJOR_LINKER_VERSION
                        Cooked payload major linker version to taint(Ex. 10)
  -mi MINOR_LINKER_VERSION, --minor-linker-version MINOR_LINKER_VERSION
                        Cooked payload minor linker version to taint(Ex. 10)
  -o OUTPUT, --output OUTPUT
                        output filename (Ex. FunTimes.exe)
  -json JSON, --json JSON
                        output json to stdout
  -s, --strings         Enable output file with strings (Ex. FunTimes.exe ->
                        FunTimes.txt)
  -vt VT_API_KEY, --vt-api-key VT_API_KEY
                        VirusTotal API Key
  -v, --verbose         increase output verbosity
  -d, --debug           enable debug logging to .pefixup.log file, default
                        WARNING only
 ```
 
### Examples
```bash
 python3 pefixup.py ~/Desktop/RickJames.exe officeupdate.exe
 python3 pefixup.py ~/Desktop/RickJames.exe officeupdate.exe -c 1568192888 -p funtimes -ma 10 -mi 1 
 python3 pefixup.py ~/Desktop/RickJames.exe officeupdate.exe -c 1568192888 -p funtimes -ma 10 -mi 1 -vt 1G23<SNIP>212FT
    or we can export the VT key 
 export PEFIXUP_VT_KEY=1G23<SNIP>212FT && python3 pefixup.py ~/Desktop/RickJames.exe officeupdate.exe
```

### Example Output
```bash
alexanders-MacBook-Pro-9:PeFixup alexanderrymdeko-harvey$ python3 pefixup.py ~/Desktop/RickJames.exe jj.exe -vt XXX

    -------------------------------
    █▀▀█ █▀▀ █▀▀ ░▀░ █░█ █░░█ █▀▀█
    █░░█ █▀▀ █▀▀ ▀█▀ ▄▀▄ █░░█ █░░█
    █▀▀▀ ▀▀▀ ▀░░ ▀▀▀ ▀░▀ ░▀▀▀ █▀▀▀
    -------------------------------                                                                                           
    
============= ORIGINAL FILE DATA =============
|-* IF LIVE OPS SAVE THIS DATA TO OP SHARE *-|
==============================================
[*] EXE metadata:
 - File Name: /Users/alexanderrymdeko-harvey/Desktop/RickJames.exe
 - e_magic value: 0x5a4d
 - Signature value: 0x4550
 - Imphash: 8d02d075ece1e0e4d14116cb66fb54ae
 - Size of executable code: 8.5KB
 - Size of executable image : 300.0KB
[*] FILE_HEADER:
 - Machine type value: 0x8664
 - TimeDateStamp value: 'Tue Feb 26 23:03:24 2019' 
[*] IMAGE_OPTIONAL_HEADER64:
 - Magic value: 0x20b
 - Major Linker Version: 0x0
 - Minor Linker Version: 0xe
 - Major OS Version: 0x6
 - Minor OS Version: 0x0
-----------------------------------------------
[*] Listing DEBUG Info:
        [*] Type Name: IMAGE_DEBUG_TYPE_ILTCG
                - Type: 14
                - TimeDateStamp value: 'Tue Feb 26 23:03:24 2019'
        [*] Type Name: IMAGE_DEBUG_TYPE_ILTCG
                - Type: 14
                - TimeDateStamp value: 'Tue Feb 26 23:03:24 2019'
        [*] Type Name: IMAGE_DEBUG_TYPE_ILTCG
                - Type: 14
                - TimeDateStamp value: 'Tue Feb 26 23:03:24 2019'
        [*] Type Name: IMAGE_DEBUG_TYPE_ILTCG
                - Type: 14
                - TimeDateStamp value: 'Tue Feb 26 23:03:24 2019'
-----------------------------------------------
[*] Listing imported DLLs...
        KERNEL32.dll
        ADVAPI32.dll
        MSVCP140.dll
        VCRUNTIME140.dll
        api-ms-win-crt-runtime-l1-1-0.dll
        api-ms-win-crt-stdio-l1-1-0.dll
        api-ms-win-crt-string-l1-1-0.dll
        api-ms-win-crt-heap-l1-1-0.dll
        api-ms-win-crt-math-l1-1-0.dll
        api-ms-win-crt-locale-l1-1-0.dll
[*] KERNEL32.dll imports:
        CloseHandle at 0x140004020 <-- [OK] = Various OS interaction
        GetLastError at 0x140004028 <-- [OK] = Exception handling
        GetCurrentProcess at 0x140004030 <-- [WARNING] = This import can be concerning, but only with other imports of concern.
        CreateRemoteThread at 0x140004038 <-- [ALERT] = This import is often flagged for remote process injection.
        OpenProcess at 0x140004040 <-- [DANGER] = Import offten flagged for dynamic function location
        VirtualAllocEx at 0x140004048 <-- [DANGER] = Import is often flagged for shellcode injection.
        WriteProcessMemory at 0x140004050 <-- [DANGER] = Import offten flagged for dynamic function location
        GetModuleHandleW at 0x140004058 <-- [DANGER] = Import offten flagged for dynamic function location
        GetProcAddress at 0x140004060 <-- [DANGER] = Import is often flagged for shellcode injection.
        CreateProcessW at 0x140004068 <-- [ALERT] = This import is often flagged for remote process injection.
        GetSystemTimeAsFileTime at 0x140004070 <-- [OK] = Various OS interaction
        GetCurrentThreadId at 0x140004078 <-- [WARNING] = This import can be concerning, but only with other imports of concern.
        GetCurrentProcessId at 0x140004080 <-- [WARNING] = This import can be concerning, but only with other imports of concern.
        QueryPerformanceCounter at 0x140004088 <-- [DANGER] = Import offten flagged for sandbox / analysis evasion
        IsDebuggerPresent at 0x140004090 <-- [ALERT] = Import offten flagged for sandbox / analysis evasion
        CreateEventW at 0x140004098 <-- [OK] = Various OS interaction
        DeleteCriticalSection at 0x1400040a0 <-- [OK] = Various OS interaction
        IsProcessorFeaturePresent at 0x1400040a8 <-- [WARNING] = This import can be concerning, but only with other imports of concern.
        TerminateProcess at 0x1400040b0 <-- [OK] = Various OS interaction
        SetUnhandledExceptionFilter at 0x1400040b8 <-- [OK] = Exception handling
        UnhandledExceptionFilter at 0x1400040c0 <-- [OK] = Exception handling
        RtlVirtualUnwind at 0x1400040c8 <-- [OK] = Exception handling
        RtlLookupFunctionEntry at 0x1400040d0 <-- [OK] = Exception handling
        RtlCaptureContext at 0x1400040d8 <-- [OK] = Exception handling
        InitializeSListHead at 0x1400040e0 <-- [OK] = Compiler optimization
[*] ADVAPI32.dll imports:
        AdjustTokenPrivileges at 0x140004000 <-- [DANGER] = Import used for token manipulation
        OpenProcessToken at 0x140004008 <-- [WARNING] = Import used for token manipulation
        LookupPrivilegeValueW at 0x140004010 <-- [WARNING] = Import used for token manipulation
[*] MSVCP140.dll imports:
        ?_Xbad_alloc@std@@YAXXZ at 0x1400040f0 <-- [UNKNOWN] = Please submit PR
        ?_Xlength_error@std@@YAXPEBD@Z at 0x1400040f8 <-- [UNKNOWN] = Please submit PR
        ?_Xout_of_range@std@@YAXPEBD@Z at 0x140004100 <-- [UNKNOWN] = Please submit PR
[*] VCRUNTIME140.dll imports:
        memcpy at 0x140004110 <-- [OK] = Various OS interaction
        __std_terminate at 0x140004118 <-- [OK] = Various OS interaction
        memmove at 0x140004120 <-- [OK] = Various OS interaction
        __std_exception_copy at 0x140004128 <-- [OK] = Various OS interaction
        __std_exception_destroy at 0x140004130 <-- [OK] = Various OS interaction
        _CxxThrowException at 0x140004138 <-- [OK] = Various OS interaction
        __CxxFrameHandler3 at 0x140004140 <-- [OK] = Various OS interaction
        memset at 0x140004148 <-- [OK] = Various OS interaction
        __C_specific_handler at 0x140004150 <-- [OK] = Various OS interaction
        __vcrt_InitializeCriticalSectionEx at 0x140004158 <-- [OK] = Various OS interaction
[-] Not printing imports of api-ms-win-crt-runtime-l1-1-0.dll no need..
[-] Not printing imports of api-ms-win-crt-stdio-l1-1-0.dll no need..
[-] Not printing imports of api-ms-win-crt-string-l1-1-0.dll no need..
[-] Not printing imports of api-ms-win-crt-heap-l1-1-0.dll no need..
[-] Not printing imports of api-ms-win-crt-math-l1-1-0.dll no need..
[-] Not printing imports of api-ms-win-crt-locale-l1-1-0.dll no need..
============= PRE-FLIGHT CHECKS ==============
|-* IF LIVE OPS SAVE THIS DATA TO OP SHARE *-|
==============================================
[*] File re-write checks:
 - SHA256 of non-cooked payload: a0ad72b91585f485e91f8a9c46a8c4e4c49cc404acc1055051071fd9762ee505
 - SHA256 of cooked payload: a0ad72b91585f485e91f8a9c46a8c4e4c49cc404acc1055051071fd9762ee505
Preflight checks: PASS
============= TAINTED FILE DATA ==============
|-* IF LIVE OPS SAVE THIS DATA TO OP SHARE *-|
==============================================
[*] Walking DOS_HEADER:
 - Target e_lfanew offset value: 0x108
 - Set e_lfanew offset + PE bytes: 0x10c
[*] Walking IMAGE_FILE_HEADER:
 - TimeDateStamp offset value: 0x110
 - TimeDateStamp hex value: 0x5c759b8c
 - TimeDateStamp int value: 1551211404
 - TimeDateStamp time date value: 2019-02-26 23:03:24
 ==> TimeDateStamp stomped start write location: 0x110
 ==> Setting TimeDateStamp stomped int value to: 1454680254
 ==> Setting TimeDateStamp stomped hex value to: 0x56b4a8be
 ==> TimeDateStamp time date value: 2016-02-05 16:50:54
[*] Walking IMAGE_OPTIONAL_HEADER:
 - Magic offset value: 0x120
 - Magic hex value: 0x20b
 - MajorLinkerVersion offset value: 0x122
 - MajorLinkerVersion hex value: 0xe
 - MajorLinkerVersion int value: 14
 - MinorLinkerVersion offset value: 0x123
 - MinorLinkerVersion hex value: 0xa
 - MinorLinkerVersion int value: 10
 ==> MajorLinkerVersion stomped start write location: 0x122
 ==> Setting MajorLinkerVersion stomped int value to: 10
 ==> Setting MajorLinkerVersion stomped hex value to: 0xa
 ==> MinorLinkerVersion stomped start write location: 0x123
 ==> Setting MinorLinkerVersion stomped int value to: 2
 ==> Setting MinorLinkerVersion stomped hex value to: 0x2
[*] DEBUG INFO:
        [*] Type: ('IMAGE_DEBUG_TYPE_CODEVIEW', 2)
                - Debug TimeDateStamp offset value: 0x2c04
                - TimeDateStamp hex value: 0x5c759b8c
                - TimeDateStamp int value: 1551211404
                - TimeDateStamp time date value: 2019-02-26 23:03:24
                ==> TimeDateStamp stomped start write location: 0x2c04
                ==> Setting TimeDateStamp stomped int value to: 1454680254
                ==> Setting TimeDateStamp stomped hex value to: 0x56b4a8be
                ==> TimeDateStamp time date value: 2016-02-05 16:50:54
                - PdbFileName offset value: 0x2f44
                - PdbFileName value: 'b'C:\\Users\\rt\\Desktop\\RickJames\\RickJames\\x64\\Release\\RickJames.pdb\x00''
                - PdbFileName null-term string: '['C', ':', '\\', 'U', 's', 'e', 'r', 's', '\\', 'r', 't', '\\', 'D', 'e', 's', 'k', 't', 'o', 'p', '\\', 'R', 'i', 'c', 'k', 'J', 'a', 'm', 'e', 's', '\\', 'R', 'i', 'c', 'k', 'J', 'a', 'm', 'e', 's', '\\', 'x', '6', '4', '\\', 'R', 'e', 'l', 'e', 'a', 's', 'e', '\\', 'R', 'i', 'c', 'k', 'J', 'a', 'm', 'e', 's', '.', 'p', 'd', 'b', '\x00']'
                ==> PdbFileName stomped start write location: 0x2f44
                ==> PdbFifleName stomped end write location: 0x2f86
                ==> Setting PdbFifleName stomped hex value to: b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        [*] Type: ('IMAGE_DEBUG_TYPE_VC_FEATURE', 12)
                - Debug TimeDateStamp offset value: 0x2c20
                - TimeDateStamp hex value: 0x5c759b8c
                - TimeDateStamp int value: 1551211404
                - TimeDateStamp time date value: 2019-02-26 23:03:24
                ==> TimeDateStamp stomped start write location: 0x2c20
                ==> Setting TimeDateStamp stomped int value to: 1454680254
                ==> Setting TimeDateStamp stomped hex value to: 0x56b4a8be
                ==> TimeDateStamp time date value: 2016-02-05 16:50:54
        [*] Type: ('IMAGE_DEBUG_TYPE_POGO', 13)
                - Debug TimeDateStamp offset value: 0x2c3c
                - TimeDateStamp hex value: 0x5c759b8c
                - TimeDateStamp int value: 1551211404
                - TimeDateStamp time date value: 2019-02-26 23:03:24
                ==> TimeDateStamp stomped start write location: 0x2c3c
                ==> Setting TimeDateStamp stomped int value to: 1454680254
                ==> Setting TimeDateStamp stomped hex value to: 0x56b4a8be
                ==> TimeDateStamp time date value: 2016-02-05 16:50:54
        [*] Type: ('IMAGE_DEBUG_TYPE_ILTCG', 14)
                - Debug TimeDateStamp offset value: 0x2c58
                - TimeDateStamp hex value: 0x5c759b8c
                - TimeDateStamp int value: 1551211404
                - TimeDateStamp time date value: 2019-02-26 23:03:24
                ==> TimeDateStamp stomped start write location: 0x2c58
                ==> Setting TimeDateStamp stomped int value to: 1454680254
                ==> Setting TimeDateStamp stomped hex value to: 0x56b4a8be
                ==> TimeDateStamp time date value: 2016-02-05 16:50:54
==============================================
|-*          RUNTIME SANITY CHECKS         *-|
==============================================
[*] SHA256 do not match, we have proper write: PASS
[*] TimeDateStamp stomped properly: PASS
[*] MajorLinkerVersion stomped properly: PASS
[*] MinorLinkerVersion stomped properly: PASS
[*] TimeDateStamp stomped properly for ('IMAGE_DEBUG_TYPE_CODEVIEW', 2): PASS
[*] TimeDateStamp stomped properly for ('IMAGE_DEBUG_TYPE_VC_FEATURE', 12): PASS
[*] TimeDateStamp stomped properly for ('IMAGE_DEBUG_TYPE_POGO', 13): PASS
[*] TimeDateStamp stomped properly for ('IMAGE_DEBUG_TYPE_ILTCG', 14): PASS
==============================================
|-*         COOKED PAYLOAD METADATA        *-|
==============================================
[*] Filename of cooked payload: jj.exe
[*] MD5 of cooked payload: 65231460be8482cd6297b0ff47a07cd7
[*] SHA1 of cooked payload: 13f0ba395f0d3e1df486941f46a9406fa779aaa9
[*] SHA256 of cooked payload: 79bb44d9a1365bfca1dd9b23e2f7220b9fc8202ba2004be256bf53458bf27e10
[*] SHA512 of cooked payload: 68becb3ba12850727543f2a092b52077122e673a24f44e994234f9925139fe9f031930751e12c0ee5e8bd45ed12de1e13e21668fdb06a01130188f4871a7e067
[*] Imphash of cooked payload: 8d02d075ece1e0e4d14116cb66fb54ae
[*] SSDeep of cooked payload: 6144:7HTMqK4TA1SjnNVAOKqWCQsKIR2ZIIt+M5co6N+3fv5RUAZ8nE:LTM14TA18nvKqtgzZIE5cnaRUO8
[*] Magic of cooked payload: PE32+ executable (console) x86-64, for MS Windows
[*] EXIF Data follows of cooked payload:
        SourceFile: /Users/alexanderrymdeko-harvey/tools/PeFixup/jj.exe
        ExifTool:ExifToolVersion: 11.2
        File:Directory: /Users/alexanderrymdeko-harvey/tools/PeFixup
        File:FileAccessDate: 2019:09:11 13:14:38+03:00
        File:FileInodeChangeDate: 2019:09:11 13:14:38+03:00
        File:FileModifyDate: 2019:09:11 13:14:38+03:00
        File:FileName: jj.exe
        File:FilePermissions: rw-r--r--
        File:FileSize: 277 kB
        File:FileType: Win64 EXE
        File:FileTypeExtension: exe
        File:MIMEType: application/octet-stream
        EXE:CodeSize: 8704
        EXE:EntryPoint: 0x2794
        EXE:ImageFileCharacteristics: Executable, Large address aware
        EXE:ImageVersion: 0.0
        EXE:InitializedDataSize: 275456
        EXE:LinkerVersion: 10.2
        EXE:MachineType: AMD AMD64
        EXE:OSVersion: 6.0
        EXE:PEType: PE32+
        EXE:Subsystem: Windows command line
        EXE:SubsystemVersion: 6.0
        EXE:TimeStamp: 2016:02:05 16:50:54+03:00
        EXE:UninitializedDataSize: 0
==============================================
|-*           RUNTIME BURNT CHECKS         *-|
==============================================
[*] Starting checks VirusTotal HASH ONLY checks
 - SHA256 of non-cooked payload is SAFE and NOT SEEN in VirusTotal: a0ad72b91585f485e91f8a9c46a8c4e4c49cc404acc1055051071fd9762ee505
 - SHA256 of cooked payload is SAFE and NOT SEEN in VirusTotal: 79bb44d9a1365bfca1dd9b23e2f7220b9fc8202ba2004be256bf53458bf27e10
 - SHA256 PE Section .text of non-cooked payload is SAFE and NOT SEEN in VirusTotal: 20287460a047d605355994e26aa552de2172ed3d8e43febb8d27ac52db99e1d3
 - SHA256 PE Section .rdata of non-cooked payload is SAFE and NOT SEEN in VirusTotal: 70ee18d4fca2c12b5183025d48e21caf4db2b98fc0d9a56460c9f064bc176468
 - SHA256 PE Section .data of non-cooked payload is SAFE and NOT SEEN in VirusTotal: cf7f2cff0f91c1d832a734f94a2ec76a52d2fc3846b4804d68e990ae536d89f6
 - SHA256 PE Section .pdata of non-cooked payload is SAFE and NOT SEEN in VirusTotal: cb5add40cc6afb7aae92d96f759d932cf97ec4087b65698f79b5430d4f40a22c
 - SHA256 PE Section .tls of non-cooked payload is SAFE and SEEN in VirusTotal: 4c6474903705cb450bb6434c29e8854f17d8324efca1fdb9ee9008599060883a
 - SHA256 PE Section .rsrc of non-cooked payload is SAFE and NOT SEEN in VirusTotal: 511460000232d2f733ea1ba0b43600e12b3d79d466afb7b12d3a196dc207472e
 - SHA256 PE Section .reloc of non-cooked payload is SAFE and NOT SEEN in VirusTotal: 987d59fb32feb52ed375d5dc31dfd1d9fb0748f4e3d39c39786c7a2a30369373
============ POST-FLIGHT CHECKS ==============
|-* IF LIVE OPS SAVE THIS DATA TO OP SHARE *-|
==============================================
[-] Strings output not enabled (Skipping): WARNING
```
