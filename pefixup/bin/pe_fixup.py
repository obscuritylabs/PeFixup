#!/usr/bin/python3.6
from pefixup.src import core_printer

import argparse
import json
import logging
import os
import sys

def main():
    """
    Print entry screen and pass execution to CLI, 
    and task core.
    :return: 
    """
    pr = core_printer.CorePrinters()
    pr.print_entry()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print('Interrupted')
        try:
            sys.exit(0)
        except SystemExit:
            os._exit(0)