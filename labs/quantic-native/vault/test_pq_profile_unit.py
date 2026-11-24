import base64,sqlite3,unittest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
import pq_profile as p
class Grant(unittest.TestCase):
 def setUp(self):
  self.db=sqlite3.connect(':memory:');self.addCleanup(self.db.close);self.root=ec.generate_private_key(ec.SECP256R1());n=self.root.public_key().public_numbers();u=lambda n:base64.urlsafe_b64encode(n.to_bytes(32,'big')).decode().rstrip('=');self.manifest={'payload':{'identitySigningPublicKey':{'x':u(n.x),'y':u(n.y)}}};self.b={'address':'lab~'+'a'*32+'@quantic','deviceId':'d-'+'b'*32};self.payload={**self.b,'kemPin':'c'*64,'dsaPin':'d'*64,'sequence':1,'active':True}
 def sign(self,payload):
  r,s=decode_dss_signature(self.root.sign(p.canonical(payload),ec.ECDSA(hashes.SHA256())));return {'payload':payload,'signature':base64.b64encode(r.to_bytes(32,'big')+s.to_bytes(32,'big')).decode()}
 def apply(self,g):return p.apply(self.db,'id',self.b,self.manifest,g)
 def test_policy(self):
  g=self.sign(self.payload);r=self.apply(g);self.assertEqual(p.vote(self.db,'id',r,r['pqBinding'])['profileSequence'],1)
  for wrong in [None,'0'*64]:
   with self.assertRaises(ValueError):p.vote(self.db,'id',r,wrong)
  with self.assertRaises(ValueError):self.apply(None)
  with self.assertRaises(ValueError):self.apply(self.sign({**self.payload,'kemPin':'e'*64,'sequence':2}))
  with self.assertRaises(ValueError):self.apply(self.sign({**self.payload,'active':False}))
  rev=self.apply(self.sign({**self.payload,'active':False,'sequence':2}));self.assertFalse(rev['pqActive'])
  with self.assertRaises(ValueError):p.vote(self.db,'id',rev,r['pqBinding'])
  with self.assertRaises(ValueError):self.apply(g)
  with self.assertRaises(ValueError):self.apply(self.sign({**self.payload,'sequence':3}))
 def test_wrong_root_signature(self):
  g=self.sign(self.payload);g['payload']={**self.payload,'kemPin':'e'*64}
  with self.assertRaises(InvalidSignature):self.apply(g)
  self.assertIsNone(p.read(self.db,'id'))
 def test_missing_grant(self):
  self.assertIsNone(self.apply(None))
  with self.assertRaises(ValueError):p.vote(self.db,'id',{},'a'*64)
if __name__=='__main__':unittest.main(verbosity=2)
