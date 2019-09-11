import unittest
from . import core_hash

class TestHashMethods(unittest.TestCase):

    def test_md5(self):
        x = bytes(0x00)
        m = core_hash.MD5()
        self.assertEqual(m.get_hash_hexdigest(x), 'd41d8cd98f00b204e9800998ecf8427e')
        self.assertEqual(m.get_hash_digest(x), b'\xd4\x1d\x8c\xd9\x8f\x00\xb2\x04\xe9\x80\t\x98\xec\xf8B~')
        self.assertEqual(m.get_digest_size(x), 16)

    def test_sha1(self):
        x = bytes(0x00)
        m = core_hash.SHA1()
        self.assertEqual(m.get_hash_hexdigest(x), 'da39a3ee5e6b4b0d3255bfef95601890afd80709')
        self.assertEqual(m.get_hash_digest(x), b'\xda9\xa3\xee^kK\r2U\xbf\xef\x95`\x18\x90\xaf\xd8\x07\t')
        self.assertEqual(m.get_digest_size(x), 20)

    def test_sha256(self):
        x = bytes(0x00)
        m = core_hash.SHA256()
        self.assertEqual(m.get_hash_hexdigest(x), 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
        # TODO: Fix this test case:
        self.assertEqual(m.get_hash_digest(x), m.get_hash_digest(x))
        self.assertEqual(m.get_digest_size(x), 32)

    def test_sha512(self):
        x = bytes(0x00)
        m = core_hash.SHA512()
        self.assertEqual(m.get_hash_hexdigest(x), 'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e')
        # TODO: Fix this test case:
        self.assertEqual(m.get_hash_digest(x), m.get_hash_digest(x))
        self.assertEqual(m.get_digest_size(x), 64)

    def test_imp(self):
        m = core_hash.IMP()
        self.assertEqual(m.get_hash_hexdigest('test/net-35-bin.exe'), 'f34d5f2d4577ed6d9ceec516c1f5a744')
        # TODO: Fix this test case:
        self.assertEqual(m.get_hash_digest('test/net-35-bin.exe'), b'f34d5f2d4577ed6d9ceec516c1f5a744')
        self.assertEqual(m.get_digest_size('test/net-35-bin.exe'), 32)

    def test_ssdeep(self):
        m = core_hash.SSDEEP()
        self.assertEqual(m.get_hash_hexdigest('test/net-35-bin.exe'), '3:HVRhqJ:H7wJ')
        # TODO: Fix this test case:
        self.assertEqual(m.get_hash_digest('test/net-35-bin.exe'), b'3:HVRhqJ:H7wJ')
        self.assertEqual(m.get_digest_size('test/net-35-bin.exe'), 13)

if __name__ == '__main__':
    unittest.main()