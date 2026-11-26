import unittest,base64
import contact_proof_feed as cpf
import dual_proof_feed as dpf
def grant(i):
 return dict(payload=dict(contactId=str(i)*64,commitment='a'*64,sequence=1,issued=1000,expires=2000,active=True),classicalSignature=base64.b64encode(b'x'*64).decode(),pqSignature=base64.b64encode(b'y'*3309).decode())
class ContactFrame(unittest.TestCase):
 def test_fixed_roundtrip(self):
  for signature,grants in ((None,[]),(b'x'*3309,[grant(1)]),(b'x'*3309,[grant(1),grant(2)])):
   frame=cpf.pack(b'lease',signature,grants);self.assertEqual(len(frame),14336)
   self.assertEqual(cpf.unpack(frame),(b'lease',signature,grants))
   for bad in (frame[:-1],frame[:-1]+b'x',b'BAD!'+frame[4:]):
    with self.assertRaises(ValueError):cpf.unpack(bad)
  with self.assertRaises(ValueError):cpf.unpack(dpf.pack(b'lease'))
  with self.assertRaises(ValueError):cpf.pack(b'lease',b'x'*3309,[grant(1)]*2)
  with self.assertRaises(ValueError):cpf.pack(b'lease',b'x'*3309,[grant(i) for i in range(3)])
