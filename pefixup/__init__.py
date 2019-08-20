from pefixup.src import core_printer
from pefixup import config

import os
import sys
import json
import logging
import argparse


def __set_logging():
    if config.LOG_LEVEL == 'CRITICAL':
        __core_logger.start(logging.CRITICAL)
    if config.LOG_LEVEL == 'ERROR':
        __core_logger.start(logging.ERROR)
    if config.LOG_LEVEL == 'WARNING':
        __core_logger.start(logging.WARNING)
    if config.LOG_LEVEL == 'INFO':
        __core_logger.start(logging.INFO)
    if config.LOG_LEVEL == 'DEBUG':
        __core_logger.start(logging.DEBUG)
