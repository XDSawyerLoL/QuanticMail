import unittest,subprocess,hashlib,tempfile,pathlib
import pq_profile as pp
import pq_dual_authority as dual
from test_pq_profile_unit import Grant
IDENTITY='a'*64
class Dual(Grant):
 def setUp(self):
  super().setUp();self.db.execute('CREATE TABLE signed_manifest(id TEXT PRIMARY KEY)');self.db.execute('INSERT INTO signed_manifest VALUES (?)',(IDENTITY,));self.key=subprocess.check_output([dual.OPENSSL,'genpkey','-algorithm','ML-DSA-65']);self.pub=subprocess.check_output([dual.OPENSSL,'pkey','-pubout','-outform','DER'],input=self.key);self.pin=dual.sha(self.pub);dual.install(self.db,IDENTITY,self.pub,self.pin)
 def apply(self,g):return pp.apply(self.db,IDENTITY,self.b,self.manifest,g)
 def proof(self,g):
  with tempfile.TemporaryDirectory() as d:
   d=pathlib.Path(d);(d/'key').write_bytes(self.key);(d/'data').write_bytes(dual.message(IDENTITY,pp.canonical(g['payload'])));return subprocess.check_output([dual.OPENSSL,'pkeyutl','-sign','-rawin','-inkey',str(d/'key'),'-in',str(d/'data')])
 def stage(self,g,s=None):dual.stage(self.db,IDENTITY,self.b,self.manifest,g,self.proof(g) if s is None else s)
 def test_policy(self):
  g=self.sign(self.payload);self.stage(g);r=self.apply(g);self.assertEqual(pp.vote(self.db,IDENTITY,r,r['pqBinding'])['profileSequence'],1)
  rev=self.sign({**self.payload,'active':False,'sequence':2});self.stage(rev)
  with self.assertRaises(ValueError):pp.vote(self.db,IDENTITY,r,r['pqBinding'])
  result=self.apply(rev);self.assertFalse(result['pqActive'])
  with self.assertRaises(ValueError):pp.vote(self.db,IDENTITY,result,result['pqBinding'])
  with self.assertRaises(ValueError):self.stage(g)
 def test_missing_grant(self):
  with self.assertRaises(ValueError):self.apply(None)
  with self.assertRaises(ValueError):self.apply(self.sign(self.payload))
  with self.assertRaises(ValueError):pp.vote(self.db,IDENTITY,{},None)
 def test_wrong_root_signature(self):
  g=self.sign(self.payload);s=self.proof(g);self.key=subprocess.check_output([dual.OPENSSL,'genpkey','-algorithm','ML-DSA-65']);
  with self.assertRaises(ValueError):self.stage(g,self.proof(g))
  with self.assertRaises(ValueError):self.stage(g,s[:-1]+bytes([s[-1]^1]))
  self.stage(g,s);self.apply(g)
  with self.assertRaises(ValueError):dual.install(self.db,IDENTITY,self.pub,self.pin)
 def test_classical_only_new_grant_denied(self):
  g=self.sign(self.payload);self.stage(g);self.apply(g)
  rev=self.sign({**self.payload,'sequence':2,'active':False})
  with self.assertRaises(ValueError):self.apply(rev)
  with self.assertRaises(ValueError):self.stage(self.sign({**self.payload,'active':False}),self.proof(g))
if __name__=='__main__':unittest.main(verbosity=2)
