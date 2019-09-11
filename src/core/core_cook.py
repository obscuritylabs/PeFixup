from typing import Tuple, Iterable, Union
from termcolor import colored, cprint
from . import core_hash
from . import core_checks
import datetime
import magic
import pyexifinfo as exif
from struct import *
from pefile import debug_types

class CoreCook():

    """
    Core Cook Class.
    """

    def __init__(self):
        """
        Init class and passed objects.
        """
        self.cook_taint()
        self.sanity_check()
        self.populate_metadata()
        self.runtime_burnt_check()

    def cook_taint(self):
        self.print_taint_payload()
        self.setup_taint()
        if self.taint:
            self.dos_header()
            self.image_file_header()
            self.image_optional_header()
            self.directory_entry_debug()
        self.taint.close()

    def dos_header(self):
        """
        typedef struct _IMAGE_DOS_HEADER {  // DOS .EXE header
            USHORT e_magic;         // Magic number
            USHORT e_cblp;          // Bytes on last page of file
            USHORT e_cp;            // Pages in file
            USHORT e_crlc;          // Relocations
            USHORT e_cparhdr;       // Size of header in paragraphs
            USHORT e_minalloc;      // Minimum extra paragraphs needed
            USHORT e_maxalloc;      // Maximum extra paragraphs needed
            USHORT e_ss;            // Initial (relative) SS value
            USHORT e_sp;            // Initial SP value
            USHORT e_csum;          // Checksum
            USHORT e_ip;            // Initial IP value
            USHORT e_cs;            // Initial (relative) CS value
            USHORT e_lfarlc;        // File address of relocation table
            USHORT e_ovno;          // Overlay number
            USHORT e_res[4];        // Reserved words
            USHORT e_oemid;         // OEM identifier (for e_oeminfo)
            USHORT e_oeminfo;       // OEM information; e_oemid specific
            USHORT e_res2[10];      // Reserved words
            LONG   e_lfanew;        // File address of new exe header
        } IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;
        """
        print("[*] Walking DOS_HEADER:")
        print(f" - Target e_lfanew offset value: {hex(self.pe.DOS_HEADER.e_lfanew)}")
        self.target_offset = self.pe.DOS_HEADER.e_lfanew + 4
        print(f" - Set e_lfanew offset + PE bytes: {hex(self.pe.DOS_HEADER.e_lfanew+4)}")

    def image_file_header(self) -> bool:
        """
        typedef struct _IMAGE_FILE_HEADER {
            USHORT  Machine;
            USHORT  NumberOfSections;
            ULONG   TimeDateStamp;
            ULONG   PointerToSymbolTable;
            ULONG   NumberOfSymbols;
            USHORT  SizeOfOptionalHeader;
            USHORT  Characteristics;
        } IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;
        """
        # now add 4 bytes to the value for the ASCII string 'PE'
        try:
            print("[*] Walking IMAGE_FILE_HEADER:")
            self.ifh_tds = self.target_offset + 4
            print(f" - TimeDateStamp offset value: {hex(self.ifh_tds)}")
            print(f" - TimeDateStamp hex value: {hex(unpack('L', self.raw[self.ifh_tds:self.ifh_tds+0x8])[0])}")
            print(f" - TimeDateStamp int value: {unpack('L', self.raw[self.ifh_tds:self.ifh_tds+0x8])[0]}")
            print(f" - TimeDateStamp time date value: {datetime.datetime.fromtimestamp(int(unpack( 'L', self.raw[self.ifh_tds:self.ifh_tds+0x8])[0]))}")
            self.taint.seek(self.ifh_tds, 0)
            self.taint.write(pack('L', self.args.compile_time))
            print(colored(f" ==> TimeDateStamp stomped start write location: {hex(self.ifh_tds)}", "cyan"))
            print(colored(f" ==> Setting TimeDateStamp stomped int value to: {self.args.compile_time}", "cyan"))
            print(colored(f" ==> Setting TimeDateStamp stomped hex value to: {hex(self.args.compile_time)}", "cyan"))
            print(colored(f" ==> TimeDateStamp time date value: {datetime.datetime.fromtimestamp(int(self.args.compile_time))}", "cyan"))
        except Exception as e:
            # return false so we can alert process of bad stomp
            print(colored(f"[!] (image_file_header()-{datetime.datetime.now()}) [ERROR]: {e}",'red'))
            return False
        return True

    def image_optional_header(self) -> bool:
        """
        typedef struct _IMAGE_OPTIONAL_HEADER {
            //
            // Standard fields.
            //
            USHORT  Magic;
            UCHAR   MajorLinkerVersion;
            UCHAR   MinorLinkerVersion;
            ULONG   SizeOfCode;
            ULONG   SizeOfInitializedData;
            ULONG   SizeOfUninitializedData;
            ULONG   AddressOfEntryPoint;
            ULONG   BaseOfCode;
            ULONG   BaseOfData;
            //
            // NT additional fields.
            //
            ULONG   ImageBase;
            ULONG   SectionAlignment;
            ULONG   FileAlignment;
            USHORT  MajorOperatingSystemVersion;
            USHORT  MinorOperatingSystemVersion;
            USHORT  MajorImageVersion;
            USHORT  MinorImageVersion;
            USHORT  MajorSubsystemVersion;
            USHORT  MinorSubsystemVersion;
            ULONG   Reserved1;
            ULONG   SizeOfImage;
            ULONG   SizeOfHeaders;
            ULONG   CheckSum;
            USHORT  Subsystem;
            USHORT  DllCharacteristics;
            ULONG   SizeOfStackReserve;
            ULONG   SizeOfStackCommit;
            ULONG   SizeOfHeapReserve;
            ULONG   SizeOfHeapCommit;
            ULONG   LoaderFlags;
            ULONG   NumberOfRvaAndSizes;
            IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
        } IMAGE_OPTIONAL_HEADER, *PIMAGE_OPTIONAL_HEADER;
        """
        try:
            print("[*] Walking IMAGE_OPTIONAL_HEADER:")
            print(f" - Magic offset value: {hex(self.pe.OPTIONAL_HEADER.__file_offset__)}")
            print(f" - Magic hex value: {hex(unpack('H', self.raw[self.pe.OPTIONAL_HEADER.__file_offset__:self.pe.OPTIONAL_HEADER.__file_offset__+0x2])[0])}")
            print(f" - MajorLinkerVersion offset value: {hex(self.pe.OPTIONAL_HEADER.__file_offset__+self.pe.OPTIONAL_HEADER.__field_offsets__['MajorLinkerVersion'])}")
            print(f" - MajorLinkerVersion hex value: {hex(unpack('B', self.raw[self.pe.OPTIONAL_HEADER.__file_offset__+self.pe.OPTIONAL_HEADER.__field_offsets__['MajorLinkerVersion']:self.pe.OPTIONAL_HEADER.__file_offset__+self.pe.OPTIONAL_HEADER.__field_offsets__['MajorLinkerVersion']+0x1])[0])}")
            print(f" - MajorLinkerVersion int value: {unpack('B', self.raw[self.pe.OPTIONAL_HEADER.__file_offset__+self.pe.OPTIONAL_HEADER.__field_offsets__['MajorLinkerVersion']:self.pe.OPTIONAL_HEADER.__file_offset__+self.pe.OPTIONAL_HEADER.__field_offsets__['MajorLinkerVersion']+0x1])[0]}")
            print(f" - MinorLinkerVersion offset value: {hex(self.pe.OPTIONAL_HEADER.__file_offset__+self.pe.OPTIONAL_HEADER.__field_offsets__['MinorLinkerVersion'])}")
            print(f" - MinorLinkerVersion hex value: {hex(unpack('B', self.raw[self.pe.OPTIONAL_HEADER.__file_offset__+self.pe.OPTIONAL_HEADER.__field_offsets__['MinorLinkerVersion']:self.pe.OPTIONAL_HEADER.__file_offset__+self.pe.OPTIONAL_HEADER.__field_offsets__['MinorLinkerVersion']+0x1])[0])}")
            print(f" - MinorLinkerVersion int value: {unpack('B', self.raw[self.pe.OPTIONAL_HEADER.__file_offset__+self.pe.OPTIONAL_HEADER.__field_offsets__['MinorLinkerVersion']:self.pe.OPTIONAL_HEADER.__file_offset__+self.pe.OPTIONAL_HEADER.__field_offsets__['MinorLinkerVersion']+0x1])[0]}")

            print(colored(f" ==> MajorLinkerVersion stomped start write location: {hex(self.pe.OPTIONAL_HEADER.__file_offset__+self.pe.OPTIONAL_HEADER.__field_offsets__['MajorLinkerVersion'])}", "cyan"))
            print(colored(f" ==> Setting MajorLinkerVersion stomped int value to: {self.args.major_linker_version}", "cyan"))
            print(colored(f" ==> Setting MajorLinkerVersion stomped hex value to: {hex(self.args.major_linker_version)}", "cyan"))
            self.taint.seek(self.pe.OPTIONAL_HEADER.__file_offset__+self.pe.OPTIONAL_HEADER.__field_offsets__['MajorLinkerVersion'], 0)
            self.taint.write(pack('B', self.args.major_linker_version))

            print(colored(f" ==> MinorLinkerVersion stomped start write location: {hex(self.pe.OPTIONAL_HEADER.__file_offset__+self.pe.OPTIONAL_HEADER.__field_offsets__['MinorLinkerVersion'])}", "cyan"))
            print(colored(f" ==> Setting MinorLinkerVersion stomped int value to: {self.args.minor_linker_version}", "cyan"))
            print(colored(f" ==> Setting MinorLinkerVersion stomped hex value to: {hex(self.args.minor_linker_version)}", "cyan"))
            self.taint.seek(self.pe.OPTIONAL_HEADER.__file_offset__+self.pe.OPTIONAL_HEADER.__field_offsets__['MinorLinkerVersion'], 0)
            self.taint.write(pack('B', self.args.minor_linker_version))
        except Exception as e:
            # return false so we can alert process of bad stomp
            print(colored(f"[!] (image_optional_header()-{datetime.datetime.now()}) [ERROR]: {e}",'red'))
            return False
        return True

    def directory_entry_debug(self) -> bool:
        """
        // Directory Entries
        // Export Directory
        #define IMAGE_DIRECTORY_ENTRY_EXPORT         0
        // Import Directory
        #define IMAGE_DIRECTORY_ENTRY_IMPORT         1
        // Resource Directory
        #define IMAGE_DIRECTORY_ENTRY_RESOURCE       2
        // Exception Directory
        #define IMAGE_DIRECTORY_ENTRY_EXCEPTION      3
        // Security Directory
        #define IMAGE_DIRECTORY_ENTRY_SECURITY       4
        // Base Relocation Table
        #define IMAGE_DIRECTORY_ENTRY_BASERELOC      5
        // Debug Directory
        #define IMAGE_DIRECTORY_ENTRY_DEBUG          6
        // Description String
        #define IMAGE_DIRECTORY_ENTRY_COPYRIGHT      7
        // Machine Value (MIPS GP)
        #define IMAGE_DIRECTORY_ENTRY_GLOBALPTR      8
        // TLS Directory
        #define IMAGE_DIRECTORY_ENTRY_TLS            9
        // Load Configuration Directory
        #define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG    10

        typedef struct _IMAGE_DATA_DIRECTORY {
            ULONG   VirtualAddress;
            ULONG   Size;
        } IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

        typedef struct _IMAGE_DEBUG_DIRECTORY {
            ULONG   Characteristics;
            ULONG   TimeDateStamp;
            USHORT  MajorVersion;
            USHORT  MinorVersion;
            ULONG   Type;
            ULONG   SizeOfData;
            ULONG   AddressOfRawData;
            ULONG   PointerToRawData;
        } IMAGE_DEBUG_DIRECTORY, *PIMAGE_DEBUG_DIRECTORY;
        """
        print("[*] DEBUG INFO:")
        status = True
        for x in self.pe.DIRECTORY_ENTRY_DEBUG:
            try:
                print(f"\t[*] Type: {debug_types[x.struct.Type]}")
                print(f"\t\t- Debug TimeDateStamp offset value: {hex(x.struct.get_field_absolute_offset('TimeDateStamp'))}")
                print(f"\t\t- TimeDateStamp hex value: {hex(unpack('L', self.raw[x.struct.get_field_absolute_offset('TimeDateStamp'):x.struct.get_field_absolute_offset('TimeDateStamp')+0x8])[0])}")
                print(f"\t\t- TimeDateStamp int value: {unpack('L', self.raw[x.struct.get_field_absolute_offset('TimeDateStamp'):x.struct.get_field_absolute_offset('TimeDateStamp')+0x8])[0]}")
                print(f"\t\t- TimeDateStamp time date value: {datetime.datetime.fromtimestamp(int(unpack('L', self.raw[x.struct.get_field_absolute_offset('TimeDateStamp'):x.struct.get_field_absolute_offset('TimeDateStamp')+0x8])[0]))}")
                self.taint.seek(x.struct.get_field_absolute_offset('TimeDateStamp'), 0)
                self.taint.write(pack('L', self.args.compile_time))
                print(colored(f"\t\t==> TimeDateStamp stomped start write location: {hex(x.struct.get_field_absolute_offset('TimeDateStamp'))}", "cyan"))
                print(colored(f"\t\t==> Setting TimeDateStamp stomped int value to: {self.args.compile_time}", "cyan"))
                print(colored(f"\t\t==> Setting TimeDateStamp stomped hex value to: {hex(self.args.compile_time)}", "cyan"))
                print(colored(f"\t\t==> TimeDateStamp time date value: {datetime.datetime.fromtimestamp(int(self.args.compile_time))}", "cyan"))
                if x.entry:
                    if x.entry.name == 'CV_INFO_PDB70':
                        # print debug strings
                        print(f"\t\t- PdbFileName offset value: {hex(x.entry.__file_offset__ + x.entry.__field_offsets__['PdbFileName'])}")
                        print(f"\t\t- PdbFileName value: '{colored(x.entry.PdbFileName,'red')}'")
                        self.taint.seek(x.entry.__file_offset__ + x.entry.__field_offsets__['PdbFileName'], 0)
                        p = self.taint.read()
                        chars = []
                        for y in p:
                            chars.append(chr(y))
                            if y == 0:
                                break
                        clean_chars = b''
                        for y in chars:
                            clean_chars += b'\x00'
                        print(f"\t\t- PdbFileName null-term string: '{colored(chars,'red')}'")
                        print(colored(f"\t\t==> PdbFileName stomped start write location: {hex(x.entry.__file_offset__ + x.entry.__field_offsets__['PdbFileName'])}", "cyan"))
                        print(colored(f"\t\t==> PdbFifleName stomped end write location: {hex(x.entry.__file_offset__ + x.entry.__field_offsets__['PdbFileName'] + len(chars))}", "cyan"))
                        print(colored(f"\t\t==> Setting PdbFifleName stomped hex value to: {clean_chars}", "cyan"))
                        self.taint.seek(x.entry.__file_offset__ + x.entry.__field_offsets__['PdbFileName'], 0)
                        self.taint.write(clean_chars)
            except Exception as e:
                print(colored(f"[!] (directory_entry_debug()-{datetime.datetime.now()}) [ERROR]: {x} = {e}",'red'))
                status = False
        return status


    def sanity_check(self):
        """ Perform some basic checks to make sure we have completed all stomps."""
        # setup new file handle
        self.setup_cooked()
        # conduct analysis
        self.print_runtime_sanity_checks()
        if not core_hash.SHA256.get_hash_hexdigest(self.cooked) == core_hash.SHA256.get_hash_hexdigest(self.raw):
            print(f"[*] SHA256 do not match, we have proper write: {colored('PASS', 'green')}")
        else:
            print(f"[*] SHA256 MATCH, we DONT have proper write: {colored('FAIL', 'red')}")
        if int(unpack('L', self.cooked[self.ifh_tds:self.ifh_tds+0x8])[0]) == self.args.compile_time:
            print(f"[*] TimeDateStamp stomped properly: {colored('PASS', 'green')}")
        else:
            print(f"[*] TimeDateStamp stomped: {colored('FAIL', 'red')}")
        # test case for major linker version
        if int(unpack('B', self.cooked[self.pe.OPTIONAL_HEADER.__file_offset__+self.pe.OPTIONAL_HEADER.__field_offsets__['MajorLinkerVersion']:self.pe.OPTIONAL_HEADER.__file_offset__+self.pe.OPTIONAL_HEADER.__field_offsets__['MajorLinkerVersion']+0x1])[0]) == self.args.major_linker_version:
            print(f"[*] MajorLinkerVersion stomped properly: {colored('PASS', 'green')}")
        else:
            print(f"[*] MajorLinkerVersion stomped properly: {colored('FAIL', 'red')}")
        # test case for minor linker version
        if int(unpack('B', self.cooked[self.pe.OPTIONAL_HEADER.__file_offset__+self.pe.OPTIONAL_HEADER.__field_offsets__['MinorLinkerVersion']:self.pe.OPTIONAL_HEADER.__file_offset__+self.pe.OPTIONAL_HEADER.__field_offsets__['MinorLinkerVersion']+0x1])[0]) == self.args.minor_linker_version:
            print(f"[*] MinorLinkerVersion stomped properly: {colored('PASS', 'green')}")
        else:
            print(f"[*] MinorLinkerVersion stomped properly: {colored('FAIL', 'red')}")
        # test to make sure debug dir are solid
        for x in self.pe.DIRECTORY_ENTRY_DEBUG:
            if unpack('L', self.cooked[x.struct.get_field_absolute_offset('TimeDateStamp'):x.struct.get_field_absolute_offset('TimeDateStamp')+0x8])[0] == self.args.compile_time:
                print(f"[*] TimeDateStamp stomped properly for {debug_types[x.struct.Type]}: {colored('PASS', 'green')}")

    def populate_metadata(self):
        """ Populate cooked metadata into our JSON model"""
        _md = self.model['cooked_payload']['metadata']
        _md['file_name'] = self.args.LIVE
        _md['md5'] = core_hash.MD5.get_hash_hexdigest(self.cooked)
        _md['sha1'] = core_hash.SHA1.get_hash_hexdigest(self.cooked)
        _md['sha256'] = core_hash.SHA256.get_hash_hexdigest(self.cooked)
        _md['sha512'] = core_hash.SHA512.get_hash_hexdigest(self.cooked)
        _md['imphash'] = core_hash.IMP.get_hash_hexdigest(self.args.LIVE)
        _md['ssdeep'] = core_hash.SSDEEP.get_hash_hexdigest(self.cooked)
        _md['magic'] = magic.from_file(self.args.LIVE)
        ex = exif.get_json(self.args.LIVE)[0]
        _md['exif'] = ex
        self.print_cooked_payload_metadata()

    def runtime_burnt_check(self) -> bool:
        self.print_runtime_burnt_checks()
        if not self.config.VT_KEY:
            # no key set for VT skip
            print(f"[*] No VirusTotal API key loaded (Skipping): {colored('WARNING', 'yellow')}")
            return False
        print(f"[*] Starting checks VirusTotal HASH ONLY checks")
        vt = core_checks.VT(core_hash.SHA256.get_hash_hexdigest(self.raw), api_key=self.config.VT_KEY)
        # check non-cooked payload
        if not vt.check_seen() and vt.check_safe():
            # we are safe bin has not been seen in wild
            print(f" - SHA256 of non-cooked payload is SAFE and NOT SEEN in VirusTotal: {colored(core_hash.SHA256.get_hash_hexdigest(self.raw), 'green')}")
        if vt.check_seen() and vt.check_safe():
            # TODO: warning for seen and alert for flagged
            print(f" - SHA256 of non-cooked payload is SAFE and SEEN in VirusTotal: {colored(core_hash.SHA256.get_hash_hexdigest(self.raw), 'yellow')}")
        if vt.check_seen() and not vt.check_safe():
            # TODO: warning for seen and alert for flagged
            print(f" - SHA256 of non-cooked payload is NOT-SAFE and SEEN in VirusTotal: {colored(core_hash.SHA256.get_hash_hexdigest(self.raw), 'red')}")

        # check new live payload
        vt = core_checks.VT(core_hash.SHA256.get_hash_hexdigest(self.cooked), api_key=self.config.VT_KEY)
        if not vt.check_seen() and vt.check_safe():
            # we are safe bin has not been seen in wild
            print(f" - SHA256 of cooked payload is SAFE and NOT SEEN in VirusTotal: {colored(core_hash.SHA256.get_hash_hexdigest(self.cooked), 'green')}")
        if vt.check_seen() and vt.check_safe():
            # TODO: warning for seen and alert for flagged
            print(f" - SHA256 of cooked payload is SAFE and SEEN in VirusTotal: {colored(core_hash.SHA256.get_hash_hexdigest(self.cooked), 'yellow')}")
        if vt.check_seen() and not vt.check_safe():
            # TODO: warning for seen and alert for flagged
            print(f" - SHA256 of cooked payload is NOT-SAFE and SEEN in VirusTotal: {colored(core_hash.SHA256.get_hash_hexdigest(self.cooked), 'red')}")

        # check of non-cooked payload sections (PE Sections)
        for x in self.pe.sections:
            name = x.Name.rstrip(b'\x00').decode("utf-8")
            sha256 = x.get_hash_sha256()
            vt = core_checks.VT(sha256, api_key=self.config.VT_KEY)
            if not vt.check_seen() and vt.check_safe():
                print(f" - SHA256 PE Section {name} of non-cooked payload is SAFE and NOT SEEN in VirusTotal: {colored(sha256, 'green')}")
            if vt.check_seen() and vt.check_safe():
                print(f" - SHA256 PE Section {name} of non-cooked payload is SAFE and SEEN in VirusTotal: {colored(sha256, 'yellow')}")
            if vt.check_seen() and not vt.check_safe():
                print(f" - SHA256 PE Section {name} of non-cooked payload is NOT-SAFE and SEEN in VirusTotal: {colored(sha256, 'red')}")


