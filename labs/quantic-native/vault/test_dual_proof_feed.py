import unittest
import dual_proof_feed as dpf
import pq_profile as pp
from test_pq_dual_unit import Dual,IDENTITY

class Feed(Dual):
 def test_frame_strict(self):
  proof=b'x'*3309
  f=dpf.pack(b'public lease',proof)
  self.assertEqual(len(f),8192);self.assertEqual(dpf.unpack(f),(b'public lease',proof))
  self.assertEqual(dpf.unpack(dpf.pack(b'public lease')),(b'public lease',None))
  for bad in (f[:-1],f[:-1]+b'x',b'BAD!'+f[4:],f[:4]+b'\x00\x00\x00\x01'+f[8:]):
   with self.assertRaises(ValueError):dpf.unpack(bad)
 def test_signed_feed_stage(self):
  self.db.execute('ALTER TABLE signed_manifest ADD COLUMN binding TEXT')
  self.db.execute('ALTER TABLE signed_manifest ADD COLUMN manifest TEXT')
  import json
  self.db.execute('UPDATE signed_manifest SET binding=?,manifest=?',(json.dumps(self.b),json.dumps(self.manifest)))
  g=self.sign(self.payload);sig=self.proof(g)
  with self.assertRaises(ValueError):dpf.stage(self.db,IDENTITY,{'pqProfile':g},None)
  with self.assertRaises(ValueError):dpf.stage(self.db,IDENTITY,{'pqProfile':g},sig[:-1]+bytes([sig[-1]^1]))
  self.assertIsNone(pp.read(self.db,IDENTITY))
  dpf.stage(self.db,IDENTITY,{'pqProfile':g},sig)
  r=self.apply(g);self.assertTrue(r['pqActive'])
  rev=self.sign({**self.payload,'sequence':2,'active':False})
  dpf.stage(self.db,IDENTITY,{'pqProfile':rev},self.proof(rev))
  r=self.apply(rev);self.assertFalse(r['pqActive'])
  with self.assertRaises(ValueError):dpf.stage(self.db,IDENTITY,{'pqProfile':g},sig)
