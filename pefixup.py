#!/usr/bin/python3.6
import argparse
from src.core import core_printer
import config
import json
import logging
import os
import sys

from src.core import core_runtime

pr = core_printer.CorePrinters()

def cli_parse():
    """
    Parse the CLI args passed to the script.
    :return: args
    """
    # required
    pr.print_entry()
    parser = argparse.ArgumentParser()
    parser.add_argument("INPUT", help="input file to process")
    parser.add_argument("LIVE", help="output file name")
    # opts
    parser.add_argument("-c", "--compile-time",
                        help="Cooked payload epoc compile time to taint", default=1454680254)

    parser.add_argument("-p", "--pdb",
                        help="Cooked payload PDB (Ex. fun)", default='pefixup')

    parser.add_argument("-ma", "--major-linker-version",
                        help="Cooked payload major linker version to taint(Ex. 10)", default=10)

    parser.add_argument("-mi", "--minor-linker-version",
                        help="Cooked payload minor linker version to taint(Ex. 10)", default=2)

    parser.add_argument("-o", "--output",
                        help="output filename (Ex. FunTimes.exe)",)

    parser.add_argument("-json", "--json",
                        help="output json to stdout",)

    parser.add_argument("-v", "--verbose", help="increase output verbosity",
                        action="store_true")

    parser.add_argument("-d", "--debug", help="enable debug logging to .pefixup.log file, default WARNING only",
                        action="store_true")
    args = parser.parse_args()
    if args.verbose:
        print("[!] Verbosity turned on")
    if args.debug:
        print("[!] Debug turned on:")
        for x in vars(args):
            print(f"   arg: ({x}) key: ({vars(args)[x]})")
    return args, parser


def main():
    """
    Print entry screen and pass execution to CLI, 
    and task core.
    :return: 
    """
    args, parser = cli_parse()
    c = core_runtime.CoreRuntime(config, args)
    c.fix_up()
    
    

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print('Interrupted')
        try:
            sys.exit(0)
        except SystemExit:
            os._exit(0)