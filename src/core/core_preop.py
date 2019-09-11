import magic
import datetime
from typing import Tuple, Iterable, Union
from pefile import debug_types
from termcolor import colored

from . import core_hash

class CorePerOp():

    """
    Core PreOp Checks Class.
    """

    def __init__(self):
        """
        Init class and passed objects.
        """
        self.print_pre_op()
        self.pre_op_metadata()
        self.pre_op_file_header()
        self.pre_op_image_opt_header()
        self.print_line_br()
        self.pre_op_debug_info()
        self.pre_op_dll_info()

    def pre_op_metadata(self):
        """ """
        s = core_hash.IMP()
        nc = self.model['non_cooked_payload']
        nc['metadata']['file_name'] = self.args.INPUT
        nc['metadata']['e_magic'] = hex(self.pe.DOS_HEADER.e_magic)
        nc['metadata']['signature'] = hex(self.pe.NT_HEADERS.Signature)
        nc['metadata']['imphash'] = s.get_hash_hexdigest(self.args.INPUT)
        nc['metadata']['executable_code_size'] = int(self.pe.OPTIONAL_HEADER.SizeOfCode) / 1024
        nc['metadata']['executable_image_size'] = int(self.pe.OPTIONAL_HEADER.SizeOfImage) / 1024
        self.print_pre_op_metadata()

    def pre_op_file_header(self):
        """ """
        nc = self.model['non_cooked_payload']
        nc['file_header']['machine_type'] = hex(self.pe.FILE_HEADER.Machine)
        nc['file_header']['timedatestamp'] = datetime.datetime.fromtimestamp(int(self.pe.FILE_HEADER.TimeDateStamp)).strftime('%c')
        self.print_pre_op_file_header()

    def pre_op_image_opt_header(self):
        """ """
        nc = self.model['non_cooked_payload']
        nc['image_optional_header64']['magic'] = hex(self.pe.OPTIONAL_HEADER.Magic)
        nc['image_optional_header64']['major_linker_version'] = hex(self.pe.OPTIONAL_HEADER.MajorImageVersion)
        nc['image_optional_header64']['minor_linker_version'] = hex(self.pe.OPTIONAL_HEADER.MajorLinkerVersion)
        nc['image_optional_header64']['major_os_version'] = hex(self.pe.OPTIONAL_HEADER.MajorOperatingSystemVersion)
        nc['image_optional_header64']['minor_os_version'] = hex(self.pe.OPTIONAL_HEADER.MinorOperatingSystemVersion)
        self.print_pre_op_image_opt_header()

    def pre_op_debug_info(self):
        """ """
        _t = {}
        try:
            for x in self.pe.DIRECTORY_ENTRY_DEBUG:
                _t['entry'] = {}
                _t['type'] = debug_types[x.struct.Type][1]
                _t['type_name'] = debug_types[x.struct.Type][0]
                _t['timedatestamp'] = datetime.datetime.fromtimestamp(int(x.struct.TimeDateStamp)).strftime('%c')
                if x.entry:
                    if x.entry.name == 'CV_INFO_PDB70':
                        _t['entry']['pdbfilename'] = x.entry.PdbFileName
                        _t['entry']['type'] = 'CV_INFO_PDB70'
                self.model['non_cooked_payload']['directory_entry_debug'].append(_t)
            self.print_pre_op_debug_info()
        except AttributeError as e:
            print(colored(f'[!] {e}','yellow'))

    def pre_op_dll_info(self):
        """ """
        print("[*] Listing imported DLLs...")
        try:
            for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                _val = {}
                print('\t' + colored(entry.dll.decode('utf-8'), 'magenta'))
                self.model['non_cooked_payload']['directory_entry_import'][entry.dll.decode('utf-8')] = []

            for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                _val = {}
                dll_name = entry.dll.decode('utf-8')
                if 'api' not in dll_name:
                    print(f"[*] {colored(dll_name, 'magenta')} imports:")
                    for func in entry.imports: 
                        func_name = func.name.decode('utf-8')
                        self.model['non_cooked_payload']['directory_entry_import'][dll_name].append({
                                'function_name': func_name,
                                'function_address': func.address
                            })
                        _s, _m = self.pre_op_dll_status(dll_name, func_name)
                        print("\t%s at 0x%08x <-- [%s] = %s" % (colored(func_name, 'blue'), 
                            func.address, colored(self.warn_level[_s], self.warn_color[_s]), 
                            colored(_m, self.warn_color[_s])))
                else:
                    print(f"[-] Not printing imports of {dll_name} no need..")
        except AttributeError as e:
            print(colored(f'[!] {e}','yellow'))

    def pre_op_dll_status(self, imp: str, func: str) -> Tuple[str, str]:
        """ """
        i = self.dirty_imports_model.get(imp, {})
        f = i.get(func, {})
        status = f.get('status', 1)
        message = f.get('message', 'Please submit PR')
        return(status, message)






