# PeFixup
PE File Blessing

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
