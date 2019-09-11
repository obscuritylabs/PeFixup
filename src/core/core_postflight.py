from typing import Tuple, Iterable, Union
from termcolor import colored, cprint
import re
from collections import namedtuple


class CorePostFlight():

    """
    Core PreFlight Checks Class.
    """

    def __init__(self):
        """
        Init class and passed objects.
        """
        self.print_post_flight()
        self.strings_bin()

    def strings_bin(self):
        if self.args.strings:
            # strings enabled
            print(f"[*] Strings output not currently supported (Skipping): {colored('WARNING', 'yellow')}")
        else:
            print(f"[-] Strings output not enabled (Skipping): {colored('WARNING', 'yellow')}")
