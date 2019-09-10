import sys
import time
import pefile
from pefile import debug_types
from termcolor import colored
import json


from . import core_printer
from . import core_preop
from . import core_model
from . import core_preflight
from . import core_cook


class CoreRuntime(core_printer.CorePrinters,
                  core_preop.CorePerOp,
                  core_preflight.CorePreFlight,
                  core_cook.CoreCook
                  ):

    """
    Core Runtime Class.
    """

    def __init__(self, config, args):
        """
        Init class and passed objects.
        """
        self.config = config
        self.args = args
        self.pe = pefile.PE(args.INPUT)
        self.model = core_model._core_schema
        self.dirty_imports_model = core_model._dirty_imports_model
        self.warn_level = core_model._warn_level
        self.warn_color = core_model._warn_color
        self.raw = self.setup_raw()
        self.live = self.setup_live()
        self.taint = None
        self.cooked = None
        core_printer.CorePrinters.__init__(self)
        core_preop.CorePerOp.__init__(self)
        core_preflight.CorePreFlight.__init__(self)
        core_cook.CoreCook.__init__(self)

    def fix_up(self):
        #print(json.dumps(self.model, indent=2))
        pass

    def setup_raw(self):
        with open(self.args.INPUT, 'rb') as f:
            raw = f.read()
        return raw

    def setup_live(self):
        with open(self.args.LIVE, 'wb') as f:
            f.write(self.raw)
        with open(self.args.LIVE, 'rb') as f:
            live_raw = f.read()
        return live_raw

    def setup_taint(self):
        self.taint  = open(self.args.LIVE, 'r+b')

    def setup_cooked(self):
        with open(self.args.LIVE, 'r+b') as f:
            self.cooked = f.read()




