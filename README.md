# PeFixup
PE File Blessing

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
