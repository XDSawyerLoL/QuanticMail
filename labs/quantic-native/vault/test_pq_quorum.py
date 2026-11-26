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
  # Independent synthetic contact provisioning; no key is accepted from message.
  sender=ec.generate_private_key(ec.SECP256R1())
  sender_pq=self.local/'sender-pq.pem'
  subprocess.run(['openssl','genpkey','-algorithm','ML-DSA-65','-out',str(sender_pq)],check=True,capture_output=True);sender_pq.chmod(0o600)
  sender_pub=subprocess.check_output(['openssl','pkey','-in',str(sender_pq),'-pubout','-outform','DER'])
  from_addr='bob~'+'1'*32+'@quantic'
  recipient_ec=ec.generate_private_key(ec.SECP256R1());ej=jwk(recipient_ec.public_key());from_dev='d-'+hashlib.sha256(('P-256:'+ej['x']+':'+ej['y']).encode()).hexdigest()[:32]
  recipient_kem=self.local/'recipient-kem.pem'
  subprocess.run(['openssl','genpkey','-algorithm','ML-KEM-768','-out',str(recipient_kem)],check=True,capture_output=True);recipient_kem.chmod(0o600)
  recipient_kem_pub=subprocess.check_output(['openssl','pkey','-in',str(recipient_kem),'-pubout','-outform','DER'])
  directory=self.local/'sender-trust.json'
  directory.write_text(json.dumps([dict(address=from_addr,deviceId=from_dev,classicalSigningSpki=base64.b64encode(sender.public_key().public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)).decode(),mlDsaSigningSpki=base64.b64encode(sender_pub).decode(),classicalEncryptionSpki=base64.b64encode(recipient_ec.public_key().public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)).decode(),mlKemEncryptionSpki=base64.b64encode(recipient_kem_pub).decode(),expires=time.time_ns()//1000000+600000)]));directory.chmod(0o600)
  # Second independently generated contact, not just a duplicated label.
  second_sign=ec.generate_private_key(ec.SECP256R1());second_enc=ec.generate_private_key(ec.SECP256R1());sj=jwk(second_enc.public_key())
  second_addr='carol~'+'2'*32+'@quantic';second_dev='d-'+hashlib.sha256(('P-256:'+sj['x']+':'+sj['y']).encode()).hexdigest()[:32]
  def public_pq(alg):
   key=subprocess.check_output(['openssl','genpkey','-algorithm',alg])
   return subprocess.check_output(['openssl','pkey','-pubout','-outform','DER'],input=key)
  def spki(key):return base64.b64encode(key.public_key().public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)).decode()
  second=dict(address=second_addr,deviceId=second_dev,classicalSigningSpki=spki(second_sign),mlDsaSigningSpki=base64.b64encode(public_pq('ML-DSA-65')).decode(),classicalEncryptionSpki=spki(second_enc),mlKemEncryptionSpki=base64.b64encode(public_pq('ML-KEM-768')).decode(),expires=time.time_ns()//1000000+600000)
  directory.write_text(json.dumps(json.loads(directory.read_text())+[second]))
  import contact_permission as cp
  import pq_dual_authority as dual
  raw_contact=json.loads(directory.read_text())[0]
  def compact_array(a):return json.dumps(a,separators=(',',':')).encode()
  cid=cp.digest(compact_array(['quantic-contact-id-lab/v1',from_addr,from_dev]))
  commitment=cp.digest(compact_array(['quantic-contact-keys-lab/v1',from_addr,from_dev]+[cp.digest(base64.b64decode(raw_contact[k])) for k in ('classicalSigningSpki','mlDsaSigningSpki','classicalEncryptionSpki','mlKemEncryptionSpki')]))
  def permission(seq,active,indices,entry=raw_contact):
   cid=cp.digest(compact_array(['quantic-contact-id-lab/v1',entry['address'],entry['deviceId']]))
   commitment=cp.digest(compact_array(['quantic-contact-keys-lab/v1',entry['address'],entry['deviceId']]+[cp.digest(base64.b64decode(entry[k])) for k in ('classicalSigningSpki','mlDsaSigningSpki','classicalEncryptionSpki','mlKemEncryptionSpki')]))
   now=time.time_ns()//1000000
   payload=dict(contactId=cid,commitment=commitment,sequence=seq,issued=now,expires=now+600000,active=active)
   raw=cp.canonical(payload);r,s=decode_dss_signature(self.root.sign(dual.message(self.id,raw),ec.ECDSA(hashes.SHA256())))
   rootfile=self.local/'synthetic-pq-root.pem';rootfile.write_bytes(self.pqroot);rootfile.chmod(0o600)
   msgfile=self.local/'contact-grant-message';msgfile.write_bytes(dual.message(self.id,raw))
   sig=subprocess.check_output(['openssl','pkeyutl','-sign','-rawin','-inkey',str(rootfile),'-in',str(msgfile)])
   rootfile.unlink()
   grant=dict(payload=payload,classicalSignature=base64.b64encode(r.to_bytes(32,'big')+s.to_bytes(32,'big')).decode(),pqSignature=base64.b64encode(sig).decode())
   if self.contact_feed:
    # The fixture is an authority publisher, never writes the witness contact DB.
    # Renew signed own lease alongside contact proof to keep test TTL bounded.
    # Refresh the independent identity lease on all four feeds, even when
    # intentionally withholding this contact update from one witness.
    # Otherwise the stale witness can lose its unrelated identity lease
    # before the second-contact test, conflating two failure modes.
    issued={}
    for i in range(4):
     original,own_sig,*previous=self.feeds[i]
     outer=json.loads(original);lease=json.loads(base64.b64decode(outer['payload']))
     now=time.time_ns()//1000000
     lease.update(issued=now,expires=now+30000);issued[i]=now
     encoded=json.dumps(lease,separators=(',',':')).encode()
     data=json.dumps(dict(payload=base64.b64encode(encoded).decode(),signature=base64.b64encode(self.registry_key.sign(b'quantic-registry-lease-lab/v1\0'+encoded)).decode())).encode()
     others=previous[0] or [] if previous else []
     updated=[g for g in others if g['payload']['contactId']!=cid]+[grant] if i in indices else others
     self.feeds[i]=(data,own_sig,updated)
    end=time.monotonic()+12
    while time.monotonic()<end:
     good=True
     for i in range(4):
      with closing(sqlite3.connect(self.nodes[i]['db'])) as conn:
       lease=conn.execute('SELECT issued,expires FROM registry_lease WHERE id=?',(self.id,)).fetchone()
       good &= bool(lease and lease[0]==issued[i] and lease[1]>time.time_ns()//1000000)
     for i in indices:
      with closing(sqlite3.connect(self.nodes[i]['db'])) as conn:
       table=conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='contact_permission'").fetchone()
       row=conn.execute('SELECT seq,denied FROM contact_permission WHERE id=? AND contact=?',(self.id,cid)).fetchone() if table else None
       good &= row==(seq,int(not active))
     if good:time.sleep(.35);break
     time.sleep(.1)
    else:self.fail('scheduled contact proof did not reach witnesses')
   else:
    for i in indices:
     with closing(sqlite3.connect(self.nodes[i]['db'])) as conn,conn:
      conn.execute('BEGIN IMMEDIATE');cp.stage(conn,self.id,grant)
   return grant
  initial_permission=permission(1,True,range(4))
  permission(1,True,range(4),second)
  args.extend([self.rootpin,self.localproof,directory])
  wrong=LocalProcess(args[:-3]+['0'*64,self.localproof,directory]);self.addCleanup(wrong.close);wrong.prompt(b' : ',PASSWORD,True);wrong.prompt(b' : ',PASSWORD,True);self.assertNotEqual(wrong.p.wait(timeout=12),0);self.assertEqual(wrong.p.stdout.read(),b'');print('incorrect independent ML-DSA root pin refused',flush=True)
  original=json.loads(self.localproof.read_text())
  for field in ('classicalSignature','pqSignature'):
   altered=dict(original);raw=bytearray(base64.b64decode(altered[field]));raw[-1]^=1;altered[field]=base64.b64encode(raw).decode()
   bad=self.local/'bad-dual-proof.json';bad.write_text(json.dumps(altered));bad.chmod(0o600)
   rejected=LocalProcess(args[:-2]+[bad,directory]);self.addCleanup(rejected.close);rejected.prompt(b' : ',PASSWORD,True);rejected.prompt(b' : ',PASSWORD,True);self.assertNotEqual(rejected.p.wait(timeout=12),0);self.assertEqual(rejected.p.stdout.read(),b'')
  print('native verifier rejected both independently corrupted signatures',flush=True)
  args[-2]='auto'
  a=Controller(args,self.appkey);self.addCleanup(a.child.close);a.child.prompt(b' : ',PASSWORD,True);a.child.prompt(b' : ',PASSWORD,True);a.nonce=unb64(a.child.reply()['session']);p=a.q('public');pub=a.q('pq-public-lab');self.assertEqual(pub['pqKem'],pins['kemPublic']);self.assertEqual(pub['pqDsa'],pins['dsaPublic'])
  print('native broker automatically verified proofs from three witnesses before fresh quorum',flush=True)
  self.assertFalse(a.q('mail-open-static-lab')['ok']);self.assertFalse(a.q('export')['ok'])
  def envelope():
   kem=self.local/'kem.der';ct=self.local/'ct';sec=self.local/'secret';kem.write_bytes(unb64(pub['pqKem']))
   subprocess.run(['openssl','pkeyutl','-encap','-pubin','-inkey',str(kem),'-keyform','DER','-out',str(ct),'-secret',str(sec)],check=True,capture_output=True)
   eph=ec.generate_private_key(ec.SECP256R1());peer=ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(),unb64(p['encryption']));z=eph.exchange(ec.ECDH(),peer);pq=sec.read_bytes();sec.unlink()
   ctx=dict(clientMessageId='synthetic-pq-mail-0001',**{'from':from_addr},fromDeviceId=from_dev,to=addr,toDeviceId=dev)
   t='\n'.join(['quantic-hybrid-envelope-context-v1',SUITE,ctx['clientMessageId'],ctx['from'],ctx['fromDeviceId'],addr,dev]);key=HKDF(algorithm=hashes.SHA256(),length=32,salt=hashlib.sha256(('quantic-hybrid-kdf-salt-v1\n'+t).encode()).digest(),info=t.encode()).derive(z+pq);iv=os.urandom(12);enc=AESGCM(key).encrypt(iv,b'{"body":"synthetic PQ"}',(t+'\nquantic-aes-gcm-aad-v1').encode());return ctx,dict(cryptoSuite=SUITE,keyMode='hybrid-static-fallback',classicalEphemeralPublicKey=jwk(eph.public_key()),pqKemCiphertext=b64(ct.read_bytes()),iv=b64(iv),ciphertext=b64(enc))
  def authenticate(ctx,env):
   j=env['classicalEphemeralPublicKey']
   raw=json.dumps(['quantic-mail-sender-auth-lab/v1',ctx['clientMessageId'],ctx['from'],ctx['fromDeviceId'],ctx['to'],ctx['toDeviceId'],env['cryptoSuite'],env['keyMode'],j['kty'],j['crv'],j['x'],j['y'],env['pqKemCiphertext'],env['iv'],env['ciphertext']],separators=(',',':')).encode()
   r,s=decode_dss_signature(sender.sign(raw,ec.ECDSA(hashes.SHA256())))
   sign_input=self.local/'sender-msg';sign_input.write_bytes(raw)
   sig=subprocess.check_output(['openssl','pkeyutl','-sign','-rawin','-inkey',str(sender_pq),'-in',str(sign_input)])
   return dict(classicalSignature=b64(r.to_bytes(32,'big')+s.to_bytes(32,'big')),pqSignature=b64(sig))
  ctx,env=envelope();auth=authenticate(ctx,env)
  self.assertFalse(a.q('mail-open-hybrid-lab',pqContext=ctx,pqEnvelope=env)['ok'])
  for name in ('classicalSignature','pqSignature'):
   sig=bytearray(unb64(auth[name]));sig[-1]^=1
   self.assertFalse(a.q('mail-open-hybrid-lab',pqContext=ctx,pqEnvelope=env,senderAuth={**auth,name:b64(sig)})['ok'])
  bad=bytearray(unb64(env['ciphertext']));bad[0]^=1
  self.assertFalse(a.q('mail-open-hybrid-lab',pqContext=ctx,pqEnvelope={**env,'ciphertext':b64(bad)},senderAuth=auth)['ok'])
  self.assertFalse(a.q('mail-open-hybrid-lab',pqContext={**ctx,'from':'eve~'+'2'*32+'@quantic'},pqEnvelope=env,senderAuth=auth)['ok'])
  self.assertEqual(self.counts(),[0]*4)
  print('unsigned, altered-signature, altered-ciphertext and unknown-sender messages refused before consent',flush=True)
  a.request('mail-open-hybrid-lab',pqContext=ctx,pqEnvelope=env,senderAuth=auth);a.child.prompt(b'[taper OUI] : ',b'NON');self.assertFalse(a.child.reply()['ok'])
  a.request('mail-open-hybrid-lab',pqContext=ctx,pqEnvelope=env,senderAuth=auth);a.child.prompt(b'[taper OUI] : ',b'OUI');self.assertEqual(json.loads(unb64(a.child.reply()['message'])),{'body':'synthetic PQ'});self.assertEqual(self.counts(),[1]*4)
  a.request('mail-open-hybrid-lab',pqContext=ctx,pqEnvelope=env,senderAuth=auth,recover=True);a.child.prompt(b'[taper OUI] : ',b'OUI');self.assertEqual(json.loads(unb64(a.child.reply()['message'])),{'body':'synthetic PQ'});self.assertEqual(self.counts(),[1]*4)
  self.assertFalse(a.q('mail-open-hybrid-lab',pqContext=ctx,pqEnvelope=env,senderAuth=auth)['ok']);self.assertFalse(a.q('mail-open-hybrid-lab',pqContext={**ctx,'toDeviceId':'d-'+'0'*32},pqEnvelope=env,senderAuth=auth)['ok'])
  ch=os.urandom(32);a.request('pq-proof-lab',pqChallenge=b64(ch));a.child.prompt(b'[taper OUI] : ',b'OUI');proof=a.child.reply();self.assertTrue(proof['ok']);self.assertEqual(self.counts(),[2]*4)
  dsa=self.local/'dsa.der';dsa.write_bytes(unb64(pub['pqDsa']));sig=self.local/'sig';sig.write_bytes(unb64(proof['pqProof']));data=self.local/'msg';data.write_bytes(('quantic-pq-device-proof-lab/v1\0'+addr+'\0'+dev+'\0'+pins['kemPin']+pins['dsaPin']).encode()+ch);subprocess.run(['openssl','pkeyutl','-verify','-pubin','-inkey',str(dsa),'-keyform','DER','-rawin','-in',str(data),'-sigfile',str(sig)],check=True,capture_output=True)
  outctx=dict(clientMessageId='native-outgoing-0001',**{'from':addr},fromDeviceId=dev,to=from_addr,toDeviceId=from_dev)
  body=b'{"body":"native outgoing"}'
  self.assertFalse(a.q('mail-seal-hybrid-lab',pqContext={**outctx,'from':from_addr},message=b64(body))['ok'])
  self.assertFalse(a.q('mail-seal-hybrid-lab',pqContext={**outctx,'toDeviceId':'d-'+'0'*32},message=b64(body))['ok'])
  a.request('mail-seal-hybrid-lab',pqContext=outctx,message=b64(body));a.child.prompt(b'[taper OUI] : ',b'NON');self.assertFalse(a.child.reply()['ok'])
  a.request('mail-seal-hybrid-lab',pqContext=outctx,message=b64(body));a.child.prompt(b'[taper OUI] : ',b'OUI');out=a.child.reply();self.assertTrue(out['ok']);self.assertEqual(self.counts(),[3]*4)
  a.request('mail-seal-hybrid-lab',pqContext=outctx,message=b64(body),recover=True);a.child.prompt(b'[taper OUI] : ',b'OUI');self.assertEqual(a.child.reply(),out);self.assertEqual(self.counts(),[3]*4)
  a.request('mail-seal-hybrid-lab',pqContext=outctx,message=b64(b'{"changed":true}'),recover=True);a.child.prompt(b'[taper OUI] : ',b'OUI');self.assertFalse(a.child.reply()['ok'])
  env=out['pqEnvelope'];sa=out['senderAuth'];j=env['classicalEphemeralPublicKey']
  transcript=json.dumps(['quantic-mail-sender-auth-lab/v1',outctx['clientMessageId'],addr,dev,from_addr,from_dev,env['cryptoSuite'],env['keyMode'],j['kty'],j['crv'],j['x'],j['y'],env['pqKemCiphertext'],env['iv'],env['ciphertext']],separators=(',',':')).encode()
  from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
  signpub=ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(),unb64(p['signing']));rs=unb64(sa['classicalSignature']);signpub.verify(encode_dss_signature(int.from_bytes(rs[:32],'big'),int.from_bytes(rs[32:],'big')),transcript,ec.ECDSA(hashes.SHA256()))
  data.write_bytes(transcript);sig.write_bytes(unb64(sa['pqSignature']));subprocess.run(['openssl','pkeyutl','-verify','-pubin','-inkey',str(dsa),'-keyform','DER','-rawin','-in',str(data),'-sigfile',str(sig)],check=True,capture_output=True)
  kemct=self.local/'native-out-ct';kemct.write_bytes(unb64(env['pqKemCiphertext']))
  sec=subprocess.check_output(['openssl','pkeyutl','-decap','-inkey',str(recipient_kem),'-in',str(kemct)])
  point=ec.EllipticCurvePublicNumbers(int.from_bytes(unb64(j['x']),'big'),int.from_bytes(unb64(j['y']),'big'),ec.SECP256R1()).public_key()
  z=recipient_ec.exchange(ec.ECDH(),point);t='\n'.join(['quantic-hybrid-envelope-context-v1',SUITE,outctx['clientMessageId'],addr,dev,from_addr,from_dev])
  ak=HKDF(algorithm=hashes.SHA256(),length=32,salt=hashlib.sha256(('quantic-hybrid-kdf-salt-v1\n'+t).encode()).digest(),info=t.encode()).derive(z+sec)
  self.assertEqual(AESGCM(ak).decrypt(unb64(env['iv']),unb64(env['ciphertext']),(t+'\nquantic-aes-gcm-aad-v1').encode()),body)
  self.assertFalse(a.q('mail-seal-hybrid-lab',pqContext=outctx,message=b64(b'{"changed":true}'))['ok'])
  print('native outgoing encryption and both signatures independently verified, denied and replayed sends refused',flush=True)
  print('explicit native recovery returned identical committed bytes without consuming another journal entry',flush=True)
  permission(2,False,(0,1,2))
  a.request('mail-seal-hybrid-lab',pqContext=outctx,message=b64(body),recover=True);a.child.prompt(b'[taper OUI] : ',b'OUI');self.assertFalse(a.child.reply()['ok'])
  for i in range(3):
   with closing(sqlite3.connect(self.nodes[i]['db'])) as conn,conn:
    with self.assertRaises(ValueError):cp.stage(conn,self.id,initial_permission)
  # Local contact still present; revocation blocks BOTH directions without
  # advancing the journal or terminating the broker on a failed precheck.
  a.request('mail-seal-hybrid-lab',pqContext={**outctx,'clientMessageId':'native-outgoing-revoked'},message=b64(body));a.child.prompt(b'[taper OUI] : ',b'OUI');self.assertFalse(a.child.reply()['ok'])
  ctx,env=envelope();a.request('mail-open-hybrid-lab',pqContext=ctx,pqEnvelope=env,senderAuth=authenticate(ctx,env));a.child.prompt(b'[taper OUI] : ',b'OUI');self.assertFalse(a.child.reply()['ok'])
  self.assertEqual(self.counts(),[3]*4)
  print('contact-only revocation blocked incoming and outgoing; old signed permission refused',flush=True)
  # Revoking Bob must not disable Carol in the same scheduled snapshot.
  a.request('mail-seal-hybrid-lab',pqContext={**outctx,'clientMessageId':'native-second-contact','to':second_addr,'toDeviceId':second_dev},message=b64(body));a.child.prompt(b'[taper OUI] : ',b'OUI');self.assertTrue(a.child.reply()['ok'])
  counts=self.counts()
  if counts!=[4]*4:
   state=[]
   for i,n in enumerate(self.nodes):
    with closing(sqlite3.connect(n['db'])) as conn:
     lease=conn.execute('SELECT expires FROM registry_lease WHERE id=?',(self.id,)).fetchone()
     state.append(dict(witness=i,count=counts[i],leaseRemainingMs=lease[0]-time.time_ns()//1000000 if lease else None))
   print('second-contact replication diagnostic',json.dumps(state),flush=True)
  self.assertEqual(counts,[4]*4)
  print('second independent contact remains authorized after first contact revocation',flush=True)
  self.assertFalse(a.q('pq-proof-lab',pqChallenge=b64(ch))['ok']);rev=self.grant(pins,2,False);self.publish_profile(rev,(0,1,2));self.wait_profile(2,1,(0,1,2));print('PQ-only revocation; classical manifest unchanged',flush=True);a.request('pq-proof-lab',pqChallenge=b64(os.urandom(32)));a.child.prompt(b'[taper OUI] : ',b'OUI');self.assertNotEqual(a.child.p.wait(timeout=12),0);self.assertEqual(a.child.p.stdout.read(),b'');self.report()
if __name__=='__main__':unittest.main(defaultTest='PQ.test_pq_gate',verbosity=2)
