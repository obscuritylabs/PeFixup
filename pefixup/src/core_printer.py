from termcolor import colored, cprint
import json


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
