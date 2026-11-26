import os,struct,unittest,zlib
from compact_registry import *
class CompactTests(unittest.TestCase):
    def test_roundtrip(self):
        for raw in (b'{}',b'x'*MAX_RAW,os.urandom(1024)):
            f=pack_lease(raw);self.assertEqual(len(f),2048);self.assertEqual(unpack_lease(f),raw)
    def test_limit_and_incompressible(self):
        for raw in (b'',b'x'*(MAX_RAW+1),os.urandom(4096)):
            with self.assertRaises(ValueError):pack_lease(raw)
    def test_reject_bomb_trailing_padding(self):
        d=zlib.compress(b'x'*(MAX_RAW+1));f=MAGIC+struct.pack('!I',len(d))+d+bytes(RESPONSE_SIZE-8-len(d))
        for bad in (f,pack_lease(b'{}')[:-1],pack_lease(b'{}')[:-1]+b'x',b'X'*RESPONSE_SIZE):
            with self.assertRaises(ValueError):unpack_lease(bad)
        d=zlib.compress(b'{}')+zlib.compress(b'extra');f=MAGIC+struct.pack('!I',len(d))+d+bytes(RESPONSE_SIZE-8-len(d))
        with self.assertRaises(ValueError):unpack_lease(f)
