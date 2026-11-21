import hashlib,json,subprocess,unittest,os,time,base64,sqlite3
from contextlib import closing
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
import pq_profile as pp
from test_compact_registry import Compact
from test_portable import BINARY,Controller,LocalProcess,PASSWORD,b64,unb64
from test_manifest_scattering import jwk
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
SUITE='QNT-HYB-P256-MLKEM768-HKDFSHA256-AES256GCM-1'
class PQ(Compact):
 def grant(self,pins,seq,active):
  p=dict(address=self.binding['address'],deviceId=self.device,kemPin=pins['kemPin'],dsaPin=pins['dsaPin'],sequence=seq,active=active)
  r,s=decode_dss_signature(self.root.sign(pp.canonical(p),ec.ECDSA(hashes.SHA256())))
  return dict(payload=p,signature=base64.b64encode(r.to_bytes(32,'big')+s.to_bytes(32,'big')).decode())
 def publish_profile(self,grant,indices=range(4)):
  now=time.time_ns()//1000000
  raw=json.dumps(dict(id=self.id,manifest=self.initial,issued=now,expires=now+30000,pqProfile=grant),separators=(',',':')).encode()
  data=json.dumps(dict(payload=base64.b64encode(raw).decode(),signature=base64.b64encode(self.registry_key.sign(b'quantic-registry-lease-lab/v1\0'+raw)).decode())).encode()
  from compact_registry import pack_lease
  pack_lease(data)
  for i in indices:self.feeds[i]=data
 def wait_profile(self,sequence,denied,indices=range(4)):
  end=time.monotonic()+12
  while time.monotonic()<end:
   good=True
   for i in indices:
    with closing(sqlite3.connect(self.nodes[i]['db'])) as c:
     row=pp.read(c,self.id);good &= bool(row and row[0]==sequence and row[3]==denied)
   if good:time.sleep(.25);return
   time.sleep(.1)
  self.fail('PQ profile did not sync')
 def test_pq_gate(self):
  side=self.local/'pq'; addr=self.binding['address']; dev=self.device
  c=LocalProcess(['--provision-pq-sidecar-lab',side,self.args[2],self.args[3],self.app,self.pin,addr,dev]);self.addCleanup(c.close);c.prompt(b' : ',PASSWORD,True);c.prompt(b' : ',PASSWORD,True);pins=c.reply();self.assertEqual(c.p.wait(timeout=8),0)
  grant=self.grant(pins,1,True);self.publish_profile(grant);self.wait_profile(1,0)
  print('signed PQ grant persisted at four witnesses',flush=True)
  legacy=LocalProcess(self.args);self.addCleanup(legacy.close);legacy.prompt(b' : ',PASSWORD,True);self.assertNotEqual(legacy.p.wait(timeout=12),0);self.assertEqual(legacy.p.stdout.read(),b'');print('classic quorum startup rejected after PQ authorization',flush=True)
  args=['--broker-software-pq-quorum-lab',*self.args[1:],side,addr,dev,pins['kemPin'],pins['dsaPin']]
  no_pin=LocalProcess(args);self.addCleanup(no_pin.close);self.assertNotEqual(no_pin.p.wait(timeout=8),0);self.assertEqual(no_pin.p.stdout.read(),b'')
  if not hasattr(self,'rootpin'):
   print('mono-authority startup refused; dual-mode network test required',flush=True);return
  args.extend([self.rootpin,self.localproof])
  wrong=LocalProcess(args[:-2]+['0'*64,self.localproof]);self.addCleanup(wrong.close);wrong.prompt(b' : ',PASSWORD,True);wrong.prompt(b' : ',PASSWORD,True);self.assertNotEqual(wrong.p.wait(timeout=12),0);self.assertEqual(wrong.p.stdout.read(),b'');print('incorrect independent ML-DSA root pin refused',flush=True)
  original=json.loads(self.localproof.read_text())
  for field in ('classicalSignature','pqSignature'):
   altered=dict(original);raw=bytearray(base64.b64decode(altered[field]));raw[-1]^=1;altered[field]=base64.b64encode(raw).decode()
   bad=self.local/'bad-dual-proof.json';bad.write_text(json.dumps(altered));bad.chmod(0o600)
   rejected=LocalProcess(args[:-1]+[bad]);self.addCleanup(rejected.close);rejected.prompt(b' : ',PASSWORD,True);rejected.prompt(b' : ',PASSWORD,True);self.assertNotEqual(rejected.p.wait(timeout=12),0);self.assertEqual(rejected.p.stdout.read(),b'')
  print('native verifier rejected both independently corrupted signatures',flush=True)
  a=Controller(args,self.appkey);self.addCleanup(a.child.close);a.child.prompt(b' : ',PASSWORD,True);a.child.prompt(b' : ',PASSWORD,True);a.nonce=unb64(a.child.reply()['session']);p=a.q('public');pub=a.q('pq-public-lab');self.assertEqual(pub['pqKem'],pins['kemPublic']);self.assertEqual(pub['pqDsa'],pins['dsaPublic'])
  self.assertFalse(a.q('mail-open-static-lab')['ok']);self.assertFalse(a.q('export')['ok'])
  def envelope():
   kem=self.local/'kem.der';ct=self.local/'ct';sec=self.local/'secret';kem.write_bytes(unb64(pub['pqKem']))
   subprocess.run(['openssl','pkeyutl','-encap','-pubin','-inkey',str(kem),'-keyform','DER','-out',str(ct),'-secret',str(sec)],check=True,capture_output=True)
   eph=ec.generate_private_key(ec.SECP256R1());peer=ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(),unb64(p['encryption']));z=eph.exchange(ec.ECDH(),peer);pq=sec.read_bytes();sec.unlink()
   ctx=dict(clientMessageId='synthetic-pq-mail-0001',**{'from':'bob~'+'1'*32+'@quantic'},fromDeviceId='d-'+'1'*32,to=addr,toDeviceId=dev)
   t='\n'.join(['quantic-hybrid-envelope-context-v1',SUITE,ctx['clientMessageId'],ctx['from'],ctx['fromDeviceId'],addr,dev]);key=HKDF(algorithm=hashes.SHA256(),length=32,salt=hashlib.sha256(('quantic-hybrid-kdf-salt-v1\n'+t).encode()).digest(),info=t.encode()).derive(z+pq);iv=os.urandom(12);enc=AESGCM(key).encrypt(iv,b'{"body":"synthetic PQ"}',(t+'\nquantic-aes-gcm-aad-v1').encode());return ctx,dict(cryptoSuite=SUITE,keyMode='hybrid-static-fallback',classicalEphemeralPublicKey=jwk(eph.public_key()),pqKemCiphertext=b64(ct.read_bytes()),iv=b64(iv),ciphertext=b64(enc))
  ctx,env=envelope();a.request('mail-open-hybrid-lab',pqContext=ctx,pqEnvelope=env);a.child.prompt(b'[taper OUI] : ',b'NON');self.assertFalse(a.child.reply()['ok'])
  a.request('mail-open-hybrid-lab',pqContext=ctx,pqEnvelope=env);a.child.prompt(b'[taper OUI] : ',b'OUI');self.assertEqual(json.loads(unb64(a.child.reply()['message'])),{'body':'synthetic PQ'});self.assertEqual(self.counts(),[1]*4)
  self.assertFalse(a.q('mail-open-hybrid-lab',pqContext=ctx,pqEnvelope=env)['ok']);self.assertFalse(a.q('mail-open-hybrid-lab',pqContext={**ctx,'toDeviceId':'d-'+'0'*32},pqEnvelope=env)['ok'])
  ch=os.urandom(32);a.request('pq-proof-lab',pqChallenge=b64(ch));a.child.prompt(b'[taper OUI] : ',b'OUI');proof=a.child.reply();self.assertTrue(proof['ok']);self.assertEqual(self.counts(),[2]*4)
  dsa=self.local/'dsa.der';dsa.write_bytes(unb64(pub['pqDsa']));sig=self.local/'sig';sig.write_bytes(unb64(proof['pqProof']));data=self.local/'msg';data.write_bytes(('quantic-pq-device-proof-lab/v1\0'+addr+'\0'+dev+'\0'+pins['kemPin']+pins['dsaPin']).encode()+ch);subprocess.run(['openssl','pkeyutl','-verify','-pubin','-inkey',str(dsa),'-keyform','DER','-rawin','-in',str(data),'-sigfile',str(sig)],check=True,capture_output=True)
  self.assertFalse(a.q('pq-proof-lab',pqChallenge=b64(ch))['ok']);rev=self.grant(pins,2,False);self.publish_profile(rev,(0,1,2));self.wait_profile(2,1,(0,1,2));print('PQ-only revocation; classical manifest unchanged',flush=True);ctx,env=envelope();a.request('mail-open-hybrid-lab',pqContext=ctx,pqEnvelope=env);a.child.prompt(b'[taper OUI] : ',b'OUI');self.assertNotEqual(a.child.p.wait(timeout=12),0);self.assertEqual(a.child.p.stdout.read(),b'');self.report()
if __name__=='__main__':unittest.main(defaultTest='PQ.test_pq_gate',verbosity=2)
