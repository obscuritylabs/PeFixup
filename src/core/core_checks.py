from abc import ABC, abstractmethod 
from typing import Tuple, Iterable, IO
import time
from virus_total_apis import PublicApi as VirusTotalPublicApi


class Checks(ABC): 
    """ abstract class for burnt checks with in PeFixup."""
    def __init__(self, sha256, api_key: str = ''):
        """
        Init class and passed objects.
        """
        self.sha256 = str(sha256)
        self.api_key = str(api_key)
        self.results = self._check()
  
    # abstract method def
    def check_seen(self) -> bool:
        """ """ 
        pass
    
    # abstract method def
    def check_safe(self) -> bool: 
        """ """
        pass

    def _check(self):
        """ """
        pass

class VT(Checks):
    """ VT checks"""
    def __init__(self, sha256: str, api_key: str = ''):
        """
        Init class and passed objects.
        """
        self.sha256 = sha256
        self.api_key = str(api_key)
        self.vt = VirusTotalPublicApi(self.api_key)
        self.results = self._check()

    def check_seen(self) -> bool:
        """ """
        if self.results['results']['response_code'] == 0:
            # if response 0: we have NOT been seen
            return False
        if self.results['results']['response_code'] == 1:
            # if response 1: we have been seen
            return True

    def check_safe(self) -> bool:
        if not self.results['results'].get('positives', False):
            # we are marked safe
            return True
        if self.results['results'].get('positives', True):
            # we are marked mal
            return False

    def _check(self):
        while True:
            results = self.vt.get_file_report(self.sha256)
            if results['response_code'] == 204:
                time.sleep(10)
                continue
            break
        return results

