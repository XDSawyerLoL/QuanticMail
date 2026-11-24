"""Disposable Linux pty test of actual software persistent executable; no real keys."""
import base64, fcntl, hashlib, json, os, pathlib, pty, select, struct, subprocess, tempfile, termios, time, unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
BINARY = pathlib.Path(__file__).resolve().parent / 'VaultIsolated-linux'
PASSWORD = b'synthetic-laboratory-only-2026'
def b64(b): return base64.urlsafe_b64encode(b).decode().rstrip('=')
def unb64(s): return base64.urlsafe_b64decode(s+'='*(-len(s)%4))
class LocalProcess:
 def __init__(self,args):
  self.master, slave = pty.openpty()
  def setup():
   os.setsid(); fcntl.ioctl(slave,termios.TIOCSCTTY,0)
  self.p=subprocess.Popen([str(BINARY),*map(str,args)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,pass_fds=(slave,),preexec_fn=setup)
  os.close(slave); self.tty=b''
 def prompt(self,expected,answer,hidden=False):
  limit=time.monotonic()+8
  while expected not in self.tty:
   if time.monotonic()>limit: raise RuntimeError('terminal prompt missing')
   if select.select([self.master],[],[],0.2)[0]: self.tty+=os.read(self.master,4096)
  preceding,self.tty=self.tty.split(expected,1)
  if PASSWORD in preceding: raise AssertionError('secret echoed')
  if hidden: assert not (termios.tcgetattr(self.master)[3]&termios.ECHO)
  os.write(self.master,answer+b'\n')
 def reply(self):
  if not select.select([self.p.stdout],[],[],8)[0]: raise RuntimeError('no result')
  return json.loads(self.p.stdout.readline())
 def close(self):
  if self.p.poll() is None:self.p.kill()
  self.p.wait(timeout=5); self.p.stdin.close();self.p.stdout.close();self.p.stderr.close();os.close(self.master)
class Controller:
 def __init__(self,args,key):
  self.child=LocalProcess(args);self.key=key;self.seq=0
 def unlock(self,password=PASSWORD):
  self.child.prompt(b' : ',password,True);self.nonce=unb64(self.child.reply()['session'])
 def request(self,op,**fields):
  self.seq+=1;body=json.dumps(dict(op=op,**fields),separators=(',',':')).encode();h=hashlib.sha256(b'quantic-vault-controller-lab/v1\0'+self.nonce+struct.pack('>I',self.seq)+body).digest()
  frame=json.dumps(dict(seq=self.seq,body=b64(body),sig=b64(self.key.sign(h)))).encode()+b'\n';self.child.p.stdin.write(frame);self.child.p.stdin.flush()
 def q(self,op,**fields): self.request(op,**fields);return self.child.reply()
class Tests(unittest.TestCase):
 def test_real_persistent_process(self):
  with tempfile.TemporaryDirectory() as d:
   vault=pathlib.Path(d)/'vault'; journal=pathlib.Path(d)/'journal';key=Ed25519PrivateKey.generate();app=b64(key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw))
   create=LocalProcess(['--provision-software-lab',vault]);self.addCleanup(create.close)
   create.prompt(b' : ',PASSWORD,True);create.prompt(b' : ',PASSWORD,True);pins=create.reply();self.assertEqual(create.p.wait(timeout=5),0);self.assertEqual(pins['backend'],'software-encrypted-persistent-lab')
   self.assertEqual(vault.stat().st_mode&0o777,0o600)
   subprocess.run([str(BINARY),'--init-replay-lab',str(journal),pins['signingPin'],pins['encryptionPin'],app],check=True)
   args=['--broker-software-guarded-lab',vault,pins['signingPin'],pins['encryptionPin'],app,journal];a=Controller(args,key);self.addCleanup(a.child.close);a.unlock();pub=a.q('public');self.assertEqual(pub['backend'],'software-encrypted-persistent-lab')
   self.assertFalse(a.q('export')['ok']);packet=a.q('seal',recipient=pub['encryption'],message=b64(b'local test'))['packet']
   a.request('open',packet=packet,approved=True);a.child.prompt(b'[taper OUI] : ',b'NON');self.assertFalse(a.child.reply()['ok'])
   a.request('open',packet=packet);a.child.prompt(b'[taper OUI] : ',b'OUI');self.assertEqual(unb64(a.child.reply()['message']),b'local test')
   a.child.p.kill();a.child.p.wait(timeout=5)
   b=Controller(args,key);self.addCleanup(b.child.close);b.unlock();self.assertEqual(b.q('public'),pub);self.assertFalse(b.q('open',packet=packet)['ok']);self.assertTrue(b.q('close')['ok']);self.assertEqual(b.child.p.wait(timeout=5),0)
   no_tty=subprocess.run([str(BINARY),*map(str,args)],input=PASSWORD+b'\n',capture_output=True,start_new_session=True,timeout=5);self.assertNotEqual(no_tty.returncode,0);self.assertIn(b'terminal required',no_tty.stderr);self.assertNotIn(PASSWORD,no_tty.stderr)
 def test_no_hardware_fallback(self):
  r=subprocess.run([str(BINARY),'--broker-guarded-lab','test','a'*64,'b'*64,'invalid','/tmp/invalid'],capture_output=True,timeout=5);self.assertNotEqual(r.returncode,0);self.assertIn(b'no software fallback',r.stderr)
if __name__=='__main__':unittest.main(verbosity=2)
