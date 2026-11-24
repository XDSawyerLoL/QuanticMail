import base64,json,subprocess,unittest, pathlib, os
BINARY=pathlib.Path(__file__).resolve().parent / ('VaultIsolated.exe' if os.name=='nt' else 'VaultIsolated-linux')
def b64(b): return base64.urlsafe_b64encode(b).decode().rstrip('=')
def unb64(s): return base64.urlsafe_b64decode(s+'='*(-len(s)%4))
class Broker:
 def __init__(self):
  self.p=subprocess.Popen([str(BINARY),'--broker-test-software'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
 def q(self,op,**kw): return self.raw(json.dumps(dict(op=op,**kw)))
 def raw(self,s):
  self.p.stdin.write(s+'\n');self.p.stdin.flush();return json.loads(self.p.stdout.readline())
 def close(self):
  if self.p.poll() is None:
   try:self.q('close')
   except (BrokenPipeError,ValueError):pass
  self.p.stdin.close();self.p.wait(timeout=5);self.p.stdout.close();self.p.stderr.close()
class Tests(unittest.TestCase):
 def setUp(self):
  self.a=Broker();self.addCleanup(self.a.close);self.b=Broker();self.addCleanup(self.b.close)
  self.pa=self.a.q('public');self.pb=self.b.q('public')
 def pack(self,msg=b'synthetic test message'):
  r=self.a.q('seal',recipient=self.pb['encryption'],message=b64(msg));self.assertTrue(r['ok']);return r['packet']
 def test_01_two_process_exchange(self):
  self.assertNotEqual(self.pa['encryption'],self.pb['encryption']);self.assertNotEqual(self.pa['signing'],self.pa['encryption'])
  for msg in [b'',b'synthetic test message',bytes(range(256))*32]:
   p=self.pack(msg);self.assertEqual(unb64(self.b.q('open',packet=p)['message']),msg)
 def test_02_wrong_recipient_and_restart(self):
  p=self.pack();self.assertFalse(self.a.q('open',packet=p)['ok']);c=Broker();self.addCleanup(c.close);self.assertFalse(c.q('open',packet=p)['ok'])
 def test_03_tampering_and_replay(self):
  p=self.pack();t=dict(p);raw=bytearray(unb64(t['ciphertext']));raw[0]^=1;t['ciphertext']=b64(raw)
  self.assertFalse(self.b.q('open',packet=t)['ok']);self.assertTrue(self.b.q('open',packet=p)['ok']);self.assertFalse(self.b.q('open',packet=p)['ok'])
 def test_04_nonce_and_ephemeral_tampering(self):
  p=self.pack();self.assertFalse(self.b.q('open',packet={**p,'nonce':b64(b'0'*12)})['ok']);self.assertFalse(self.b.q('open',packet={**p,'ephemeral':self.pa['encryption']})['ok'])
 def test_05_proof_requires_issued_challenge_and_approval(self):
  c=self.a.q('issue')['challenge'];self.assertFalse(self.b.q('prove',challenge=c,approved=True)['ok']);self.assertFalse(self.a.q('prove',challenge=c,approved=False)['ok']);self.assertFalse(self.a.q('prove',challenge={**c,'scope':'root-sign'},approved=True)['ok']);self.assertTrue(self.a.q('prove',challenge=c,approved=True)['ok']);self.assertFalse(self.a.q('prove',challenge=c,approved=True)['ok'])
 def test_06_no_exports_or_general_signatures(self):
  for op in ['export','private','sign','import','root-sign']:
   self.assertFalse(self.a.q(op)['ok'])
  self.assertEqual(set(self.pa),{'ok','backend','signing','encryption'});self.assertEqual(self.pa['backend'],'software-test-only')
 def test_07_malformed_and_size_limits(self):
  self.assertFalse(self.a.raw('{bad')['ok']);self.assertFalse(self.a.raw('{"op":"public","extra":1}')['ok']);self.assertFalse(self.a.raw('{"op":"public"} {"op":"public"}')['ok']);self.assertFalse(self.a.q('seal',recipient=self.pb['encryption'],message=b64(b'x'*8193))['ok']);self.assertFalse(self.a.q('seal',recipient=b64(b'0'*65),message='x')['ok'])
 def test_08_independent_ciphertexts(self):
  p=self.pack();q=self.pack();self.assertNotEqual(p,q);self.assertTrue(self.b.q('open',packet=p)['ok']);self.assertTrue(self.b.q('open',packet=q)['ok'])
 def test_09_native_refuses_linux(self):
  if os.name!='nt':
   r=subprocess.run([str(BINARY),'--broker-lab'],input='',capture_output=True,text=True,timeout=5);self.assertNotEqual(r.returncode,0);self.assertIn('no software fallback',r.stderr)
 def test_10_budget(self):
  for _ in range(255): self.assertTrue(self.a.q('public')['ok'])
  self.a.p.stdin.write('{"op":"public"}\n');self.a.p.stdin.flush();self.assertEqual(self.a.p.stdout.readline(),'');self.assertNotEqual(self.a.p.wait(timeout=5),0)
if __name__=='__main__':unittest.main(verbosity=2)
