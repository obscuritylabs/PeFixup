from typing import Tuple, Iterable, Union
from termcolor import colored, cprint
from . import core_hash

class CorePreFlight():

    """
    Core PreFlight Checks Class.
    """

    def __init__(self):
        """
        Init class and passed objects.
        """
        self.print_pre_flight()
        self.pre_flight()

    def pre_flight(self):
        preflight = False
        preflight = self.re_write_check()
        if preflight:
            print(f"Preflight checks: {colored('PASS', 'green')}")
        else:
            print(colored(f" - SHA256 of cooked payload DOES NOT MATCH, somthing is wrong..", 'red'))
        self.model['preflight_checks']['preflight'] = preflight

    def re_write_check(self) -> bool:
        """ """
        s = core_hash.SHA256()
        preflight = True
        print("[*] File re-write checks:")
        self.model['preflight_checks']['rewrite']['non_cooked_sha256'] = s.get_hash_hexdigest(self.raw)
        self.model['preflight_checks']['rewrite']['cooked_sha256'] = s.get_hash_hexdigest(self.live)
        print(f" - SHA256 of non-cooked payload: {colored(s.get_hash_hexdigest(self.raw), 'yellow')}")
        print(f" - SHA256 of cooked payload: {colored(s.get_hash_hexdigest(self.live), 'yellow')}")
        if s.get_hash_hexdigest(self.live) != s.get_hash_hexdigest(self.raw):
            preflight = False
        if preflight:
            return True
        return False
