from abc import ABC, abstractmethod 
from typing import Tuple, Iterable, IO
import hashlib
import pefile
import magic
import ssdeep

class Hashing(ABC): 
    """ abstract class for hashing with in PeFixup."""
  
    # abstract method def
    @staticmethod
    def get_hash_digest(file_handle: IO[bytes]) -> bytes:
        """ Like digest() except the digest is returned as a 
        string of double length, containing only hexadecimal digits. 
        This may be used to exchange the value safely in email or 
        other non-binary environments.""" 
        pass
    
    # abstract method def
    @staticmethod
    def get_hash_hexdigest(file_handle: IO[bytes]) -> str: 
        """ Like digest() except the digest is returned as a 
        string of double length, containing only hexadecimal 
        digits. This may be used to exchange the value safely 
        in email or other non-binary environments."""
        pass

    # abstract method def
    @staticmethod
    def get_digest_size(file_handle: IO[bytes]) -> int:
        """ The size of the resulting hash in bytes."""
        pass

class MD5(Hashing):
    """ MD5 hashing"""

    @staticmethod
    def get_hash_digest(file_handle: IO[bytes]) -> bytes:
        return hashlib.md5(file_handle).digest()

    @staticmethod
    def get_hash_hexdigest(file_handle: IO[bytes]) -> str:
        return hashlib.md5(file_handle).hexdigest()

    @staticmethod
    def get_digest_size(file_handle: IO[bytes]) -> int:
        return hashlib.md5(file_handle).digest_size

class SHA1(Hashing):
    """ SHA256 hashing"""

    @staticmethod
    def get_hash_digest(file_handle: IO[bytes]) -> bytes:
        return hashlib.sha1(file_handle).digest()

    @staticmethod
    def get_hash_hexdigest(file_handle: IO[bytes]) -> str:
        return hashlib.sha1(file_handle).hexdigest()
    
    @staticmethod      
    def get_digest_size(file_handle: IO[bytes]) -> int:
        return hashlib.sha1(file_handle).digest_size

class SHA256(Hashing):
    """ SHA256 hashing"""

    @staticmethod
    def get_hash_digest(file_handle: IO[bytes]) -> bytes:
        return hashlib.sha256(file_handle).digest()

    @staticmethod
    def get_hash_hexdigest(file_handle: IO[bytes]) -> str:
        return hashlib.sha256(file_handle).hexdigest()

    @staticmethod  
    def get_digest_size(file_handle: IO[bytes]) -> int:
        return hashlib.sha256(file_handle).digest_size

class SHA512(Hashing):
    """ SHA256 hashing"""

    @staticmethod
    def get_hash_digest(file_handle: IO[bytes]) -> bytes:
        return hashlib.sha512(file_handle).digest()

    @staticmethod
    def get_hash_hexdigest(file_handle: IO[bytes]) -> str:
        return hashlib.sha512(file_handle).hexdigest()
       
    @staticmethod 
    def get_digest_size(file_handle: IO[bytes]) -> int:
        return hashlib.sha512(file_handle).digest_size

class IMP(Hashing):
    """ SHA256 hashing"""

    @staticmethod
    def get_hash_digest(file_handle: str) -> bytes:
        pe = pefile.PE(file_handle)
        return bytes(str.encode(pe.get_imphash()))

    @staticmethod
    def get_hash_hexdigest(file_handle: str) -> str:
        pe = pefile.PE(file_handle)
        return pe.get_imphash()
    
    @staticmethod
    def get_digest_size(file_handle: str) -> int:
        pe = pefile.PE(file_handle)
        x = bytes(str.encode(pe.get_imphash()))
        return len(x)

class SSDEEP(Hashing):
    """ SSDEEP hashing"""

    @staticmethod
    def get_hash_digest(file_handle: IO[bytes]) -> bytes:
        return bytes(str.encode(ssdeep.hash(file_handle)))

    @staticmethod
    def get_hash_hexdigest(file_handle: IO[bytes]) -> str:
        return ssdeep.hash(file_handle)
    
    @staticmethod
    def get_digest_size(file_handle: IO[bytes]) -> int:
        x = bytes(str.encode(ssdeep.hash(file_handle)))
        return len(x)







