"""Real native PQ broker with four independently pinned dual-authority databases."""
import unittest,subprocess,tempfile,pathlib,sqlite3,json
from contextlib import closing
from test_pq_quorum import PQ
import pq_dual_authority as dual
import pq_profile as pp
import dual_proof_feed as dpf
import contact_proof_feed as cpf
class DualNetwork(PQ):
 dual_feed=True
 contact_feed=True
 response_size=cpf.RESPONSE_SIZE
 def frame(self,i):
  raw=self.feeds[i]
  return cpf.pack(*raw) if isinstance(raw,tuple) else cpf.pack(raw)
 def setUp(self):
  super().setUp()
  self.pqroot=subprocess.check_output([dual.OPENSSL,'genpkey','-algorithm','ML-DSA-65']);pub=subprocess.check_output([dual.OPENSSL,'pkey','-pubout','-outform','DER'],input=self.pqroot);self.rootpin=dual.sha(pub);self.pqrootpub=pub
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
  if grant['payload']['active']:
   from cryptography.hazmat.primitives import serialization
   self.localproof=self.local/'dual-proof.json'
   wire=dict(sequence=grant['payload']['sequence'],classicalRoot=base64.b64encode(self.root.public_key().public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)).decode(),pqRoot=base64.b64encode(self.pqrootpub).decode(),classicalSignature=grant['signature'],pqSignature=base64.b64encode(sig).decode())
   self.localproof.write_text(json.dumps(wire));self.localproof.chmod(0o600)
  for i in indices:
   old=self.feeds[i];self.feeds[i]=(data,sig,old[2] if isinstance(old,tuple) and len(old)==3 else None)
 def wait_profile(self,sequence,denied,indices=range(4)):
  super().wait_profile(sequence,denied,indices)
  for i in indices:
   with closing(sqlite3.connect(self.nodes[i]['db'])) as c:
    old=pp.read(c,self.id);s=dual.staged(c,self.id);self.assertEqual(old[1],dual.combined_digest(self.rootpin,s[1]))
  print('dual authorization persisted, exact root and grant digest',sequence,'denied',denied,flush=True)
if __name__=='__main__':unittest.main(defaultTest='DualNetwork.test_pq_gate',verbosity=2)
