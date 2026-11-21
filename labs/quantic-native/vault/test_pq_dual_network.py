"""Real native PQ broker with four independently pinned dual-authority databases."""
import unittest,subprocess,tempfile,pathlib,sqlite3,json
from contextlib import closing
from test_pq_quorum import PQ
import pq_dual_authority as dual
import pq_profile as pp
import dual_proof_feed as dpf
class DualNetwork(PQ):
 dual_feed=True
 response_size=dpf.RESPONSE_SIZE
 def frame(self,i):
  raw=self.feeds[i]
  return dpf.pack(*raw) if isinstance(raw,tuple) else dpf.pack(raw)
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
  import time,base64
  now=time.time_ns()//1000000
  raw=json.dumps(dict(id=self.id,manifest=self.initial,issued=now,expires=now+30000,pqProfile=grant),separators=(',',':')).encode()
  data=json.dumps(dict(payload=base64.b64encode(raw).decode(),signature=base64.b64encode(self.registry_key.sign(b'quantic-registry-lease-lab/v1\0'+raw)).decode())).encode()
  dpf.pack(data,sig)
  for i in indices:self.feeds[i]=(data,sig)
 def wait_profile(self,sequence,denied,indices=range(4)):
  super().wait_profile(sequence,denied,indices)
  for i in indices:
   with closing(sqlite3.connect(self.nodes[i]['db'])) as c:
    old=pp.read(c,self.id);s=dual.staged(c,self.id);self.assertEqual(old[1],dual.combined_digest(self.rootpin,s[1]))
  print('dual authorization persisted, exact root and grant digest',sequence,'denied',denied,flush=True)
if __name__=='__main__':unittest.main(defaultTest='DualNetwork.test_pq_gate',verbosity=2)
