"""Real native PQ broker with four independently pinned dual-authority databases."""
import unittest,subprocess,tempfile,pathlib,sqlite3,json
from contextlib import closing
from test_pq_quorum import PQ
import pq_dual_authority as dual
import pq_profile as pp
class DualNetwork(PQ):
 def setUp(self):
  super().setUp()
  self.pqroot=subprocess.check_output([dual.OPENSSL,'genpkey','-algorithm','ML-DSA-65']);pub=subprocess.check_output([dual.OPENSSL,'pkey','-pubout','-outform','DER'],input=self.pqroot);self.rootpin=dual.sha(pub)
  for n in self.nodes:
   with closing(sqlite3.connect(n['db'])) as c,c:
    c.execute('BEGIN IMMEDIATE');dual.install(c,self.id,pub,self.rootpin)
  print('four witnesses independently pinned ML-DSA-65 root',flush=True)
 def publish_profile(self,grant,indices=range(4)):
  with tempfile.TemporaryDirectory() as d:
   d=pathlib.Path(d);(d/'key').write_bytes(self.pqroot);(d/'data').write_bytes(dual.message(self.id,pp.canonical(grant['payload'])));sig=subprocess.check_output([dual.OPENSSL,'pkeyutl','-sign','-rawin','-inkey',str(d/'key'),'-in',str(d/'data')])
  for i in indices:
   with closing(sqlite3.connect(self.nodes[i]['db'])) as c,c:
    c.execute('BEGIN IMMEDIATE');dual.stage(c,self.id,self.binding,self.initial,grant,sig)
  super().publish_profile(grant,indices)
 def wait_profile(self,sequence,denied,indices=range(4)):
  super().wait_profile(sequence,denied,indices)
  for i in indices:
   with closing(sqlite3.connect(self.nodes[i]['db'])) as c:
    old=pp.read(c,self.id);s=dual.staged(c,self.id);self.assertEqual(old[1],dual.combined_digest(self.rootpin,s[1]))
  print('dual authorization persisted, exact root and grant digest',sequence,'denied',denied,flush=True)
if __name__=='__main__':unittest.main(defaultTest='DualNetwork.test_pq_gate',verbosity=2)
