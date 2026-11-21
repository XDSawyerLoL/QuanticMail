import unittest
import contact_proof_feed as cpf
import dual_proof_feed as dpf
class ContactFrame(unittest.TestCase):
 def test_fixed_roundtrip(self):
  g={'payload':{'active':True},'pqSignature':'X'*4412}
  for signature,grant in ((None,None),(b'x'*3309,g)):
   frame=cpf.pack(b'lease',signature,grant);self.assertEqual(len(frame),12288)
   self.assertEqual(cpf.unpack(frame),(b'lease',signature,grant))
   for bad in (frame[:-1],frame[:-1]+b'x',b'BAD!'+frame[4:],frame[:4]+b'\xff'*4+frame[8:]):
    with self.assertRaises(ValueError):cpf.unpack(bad)
  with self.assertRaises(ValueError):cpf.unpack(dpf.pack(b'lease'))
  with self.assertRaises(ValueError):cpf.pack(b'lease',b'x'*3309,{'oversize':'x'*8000})
