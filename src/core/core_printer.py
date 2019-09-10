from termcolor import colored, cprint
import json
import pprint
import magic
from . import core_hash

class CorePrinters(object):
    """
    Core class: handles all data output within the project.
    """

    _branding_screen = """
    *----------------------------------*
    | 
    *----------------------------------*
    """

    __title_screen = """
    -------------------------------
    █▀▀█ █▀▀ █▀▀ ░▀░ █░█ █░░█ █▀▀█
    █░░█ █▀▀ █▀▀ ▀█▀ ▄▀▄ █░░█ █░░█
    █▀▀▀ ▀▀▀ ▀░░ ▀▀▀ ▀░▀ ░▀▀▀ █▀▀▀
    -------------------------------                                                                                           
    """

    def __init__(self):
        """
        INIT class object and define
        statics.
        """
        self.print_green = lambda x: cprint(x, 'green')
        self.print_green_on_bold = lambda x: cprint(x, 'green', attrs=['bold'])
        self.print_yellow = lambda x: cprint(x, 'yellow')
        self.print_yellow_on_bold = lambda x: cprint(
            x, 'yellow', attrs=['bold'])
        self.print_red = lambda x: cprint(x, 'red')
        self.print_red_on_bold = lambda x: cprint(x, 'red', attrs=['bold'])
        self.print_white = lambda x: cprint(x, 'white')

    def blue_text(self, msg):
        """
        Return green text obj.
        :param msg: TEXT
        :return: OBJ
        """
        s = colored(' [*] ', color='blue')
        msg = s + msg
        return msg

    def green_text(self, msg):
        """
        Return green text obj.
        :param msg: TEXT
        :return: OBJ
        """
        s = colored(' [+] ', color='green')
        msg = s + msg
        return msg

    def print_model(self):
        """ """
        pprint.pprint(self.model)

    def print_entry(self):
        """ """
        self.print_green_on_bold(self.__title_screen)

    def print_pre_op(self):
        """ """
        print("============= ORIGINAL FILE DATA =============")
        print("|-* IF LIVE OPS SAVE THIS DATA TO OP SHARE *-|")
        print("==============================================")

    def print_pre_flight(self):
        """ """
        print("============= PRE-FLIGHT CHECKS ==============")
        print("|-* IF LIVE OPS SAVE THIS DATA TO OP SHARE *-|")
        print("==============================================")

    def print_line_br(self):
        """ ."""
        print("-----------------------------------------------")

    def print_pre_op_metadata(self):
        """ """
        print("[*] EXE metadata:")
        print(f" - File Name: {colored(self.model['non_cooked_payload']['metadata']['file_name'], 'yellow')}")
        print(f" - e_magic value: {self.model['non_cooked_payload']['metadata']['e_magic']}")
        print(f" - Signature value: {self.model['non_cooked_payload']['metadata']['signature']}")
        print(f" - Imphash: {self.model['non_cooked_payload']['metadata']['imphash']}")
        print(f" - Size of executable code: {self.model['non_cooked_payload']['metadata']['executable_code_size']}KB")
        print(f" - Size of executable image : {self.model['non_cooked_payload']['metadata']['executable_image_size']}KB")

    def print_pre_op_file_header(self):
        """ """
        print("[*] FILE_HEADER:")
        print(f" - Machine type value: {self.model['non_cooked_payload']['file_header']['machine_type']}")
        print(f" - TimeDateStamp value: '{self.model['non_cooked_payload']['file_header']['timedatestamp']}' ")

    def print_pre_op_image_opt_header(self):
        """ """
        print("[*] IMAGE_OPTIONAL_HEADER64:")
        print(f" - Magic value: {self.model['non_cooked_payload']['image_optional_header64']['magic']}")
        print(f" - Major Linker Version: {self.model['non_cooked_payload']['image_optional_header64']['major_linker_version']}")
        print(f" - Minor Linker Version: {self.model['non_cooked_payload']['image_optional_header64']['minor_linker_version']}")
        print(f" - Major OS Version: {self.model['non_cooked_payload']['image_optional_header64']['major_os_version']}")
        print(f" - Minor OS Version: {self.model['non_cooked_payload']['image_optional_header64']['minor_os_version']}")

    def print_pre_op_debug_info(self):
        """ """
        print("[*] Listing DEBUG Info:")
        for x in self.model['non_cooked_payload']['directory_entry_debug']:
            print(f"\t[*] Type Name: {x['type_name']}")
            print(f"\t\t- Type: {x['type']}")
            print(f"\t\t- TimeDateStamp value: '{x['timedatestamp']}'")
            if x.get('entry'):
                if x['entry'].get('type') == 'CV_INFO_PDB70':
                    # print debug strings
                    print(f"\t\t- PdbFileName type: '{x['entry']['type']}'")
                    print(f"\t\t- PdbFileName value: '{colored(x['entry'],'red')}'")
        self.print_line_br()

    def print_taint_payload(self):
        print("============= TAINTED FILE DATA ==============")
        print("|-* IF LIVE OPS SAVE THIS DATA TO OP SHARE *-|")
        print("==============================================")

    def print_runtime_sanity_checks(self):
        print("==============================================")
        print("|-*          RUNTIME SANITY CHECKS         *-|")
        print("==============================================")

    def print_runtime_burnt_checks(self):
        print("==============================================")
        print("|-*           RUNTIME BURNT CHECKS         *-|")
        print("==============================================")

    def print_cooked_payload_metadata(self):
        """ """
        _md = self.model['cooked_payload']['metadata']
        print("==============================================")
        print("|-*         COOKED PAYLOAD METADATA        *-|")
        print("==============================================")
        print(f"[*] Filename of cooked payload: {colored(_md['file_name'], 'green')}")
        print(f"[*] MD5 of cooked payload: {colored(_md['md5'], 'green')}")
        print(f"[*] SHA1 of cooked payload: {colored(_md['sha1'], 'green')}")
        print(f"[*] SHA256 of cooked payload: {colored(_md['sha256'], 'green')}")
        print(f"[*] SHA512 of cooked payload: {colored(_md['sha512'], 'green')}")
        print(f"[*] Imphash of cooked payload: {colored(_md['imphash'], 'green')}")
        print(f"[*] SSDeep of cooked payload: {colored(_md['ssdeep'], 'green')}")
        print(f"[*] Magic of cooked payload: {colored(_md['magic'], 'green')}")
        print(f"[*] EXIF Data follows of cooked payload:")
        for x in _md['exif']:
            print(f"\t{x}: { colored(_md['exif'][x],'green')}")







