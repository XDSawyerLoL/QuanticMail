import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync,randomBytes} from 'node:crypto';
import {win32} from 'node:path';
import {
 verifyWindowsTwoHostReadiness,runWindowsTwoHostReadiness
} from '../desktop/native-windows-mail-readiness.mjs';

const hash=x=>createHash('sha256').update(x).digest('hex');
const hex=()=>randomBytes(32).toString('hex');
const dir='C:\\QuanticLab\\Alice',carrierDir='C:\\QuanticLab\\AliceCarrier';
const binary='C:\\QuanticLab\\bin\\Vault-PQ-lab.exe';
const binarySha256='1'.repeat(64);
const now=Date.now();
function participant(name,char){
 const address=name+'~'+char.repeat(32)+'@quantic',deviceId='d-'+char.repeat(32);
 const ec=()=>generateKeyPairSync('ec',{namedCurve:'prime256v1'}).publicKey;
 const signing=ec(),encryption=ec(),kem=generateKeyPairSync('ml-kem-768').publicKey,dsa=generateKeyPairSync('ml-dsa-65').publicKey;
 const mk=(key)=>{const spki=key.export({type:'spki',format:'der'});return {pin:hash(spki),spki:spki.toString('base64')};};
 const s=mk(signing),e=mk(encryption),k=mk(kem),d=mk(dsa);
 return{address,deviceId,rootPin:hex(),pqRootPin:hex(),
  classicalSigningPin:s.pin,classicalEncryptionPin:e.pin,mlKemPin:k.pin,mlDsaPin:d.pin,
  contact:{address,deviceId,classicalSigningSpki:s.spki,
   classicalEncryptionSpki:e.spki,mlKemEncryptionSpki:k.spki,
   mlDsaSigningSpki:d.spki,expires:now+3600000}};
}
function fixture(){
 const self=participant('alice','a'),peer=participant('bobby','b');
 const authorities=Array.from({length:4},(_,i)=>{
  const pub=generateKeyPairSync('ed25519').publicKey.export({type:'spki',format:'der'});
  return{url:'https://127.0.0.1:'+(45001+i)+'/native-checkpoint',
   pin:hash(pub),tlsPin:hex(),publicKey:pub.toString('base64url')};
 });
 const trust={format:'quantic-two-host-trust-lab/v1',labOnly:true,
  self:{...self},peer:{...peer},
  authorities:authorities.map(({pin,tlsPin})=>({pin,tlsPin})),carrierRole:'client'};
 delete trust.self.contact;delete trust.peer.contact;
 const cfg={labOnly:true,signingPin:self.classicalSigningPin,
  encryptionPin:self.classicalEncryptionPin,
  windowsLab:{enabled:true,dir},
  pqMode:{enabled:true,address:self.address,deviceId:self.deviceId,
   rootPin:self.pqRootPin,kemPin:self.mlKemPin,dsaPin:self.mlDsaPin,
   authority:{authorities,caFile:win32.join(dir,'peer-ca.pem'),
    clientCertFile:win32.join(dir,'peer-client-crt.pem'),
    clientKeyFile:win32.join(dir,'peer-client-key.pem')}},
  windowsScattering:{enabled:true,address:self.address,deviceId:self.deviceId,
   receiptKeyFile:win32.join(dir,'receipt.key'),
   token:'T'.repeat(64),endpoint:'http://127.0.0.1:49901/'}};
 const carrier={labOnly:true,role:'client',secretHex:hex(),epochHex:hex(),
  recvPort:49902,httpPort:49901,
  queueDir:win32.join(carrierDir,'queue'),stateDir:win32.join(carrierDir,'state')};
 return {cfg,contacts:[peer.contact],carrier,trust,self,peer};
}
const verify=f=>verifyWindowsTwoHostReadiness(f.cfg,f.contacts,f.carrier,f.trust,{now,carrierDir});
test('offline readiness pins 4 independent mTLS signers + TLS certificates, one peer and client loopback carrier',()=>{
 const f=fixture(),r=verify(f);
 assert.equal(r.status,'offline-public-anchors-verified');
 assert.equal(r.authorityCount,4);assert.equal(r.contactPinsVerified,true);
 assert.equal(r.authorityQuorumVerified,false);assert.equal(r.remoteTransportVerified,false);
 assert.equal(r.liveAccountEnrollmentAuthorized,false);
 const raw=JSON.stringify(r);
 assert.equal(raw.includes(f.carrier.secretHex),false);
 assert.equal(raw.includes(f.carrier.epochHex),false);
 assert.equal(raw.includes(f.cfg.windowsScattering.token),false);
 assert.equal(raw.includes('peer-client-key.pem'),false);
});
test('malicious authority substitution, missing 3-of-4 setup, TLS repin and authority key swap all rejected',()=>{
 const f=fixture();
 for(const change of [
  g=>{g.cfg.pqMode.authority.authorities[0].tlsPin='f'.repeat(64);},
  g=>{g.cfg.pqMode.authority.authorities[0].publicKey=g.cfg.pqMode.authority.authorities[1].publicKey;},
  g=>{g.cfg.pqMode.authority.authorities[0].url='http://127.0.0.1:45001/native-checkpoint';},
  g=>{g.cfg.pqMode.authority.authorities[0].url='https://evil.example/native-checkpoint?token=t';},
  g=>{g.cfg.pqMode.authority.authorities.pop();},
  g=>{g.trust.authorities[1].pin=g.trust.authorities[0].pin;},
  g=>{g.cfg.pqMode.authority.caFile='C:\\other\\ca.pem';},
  g=>{g.cfg.pqMode.rootPin='0'.repeat(64);}
 ]){const g=structuredClone(f);change(g);assert.throws(()=>verify(g));}
});
test('wrong owner/recipient, forged contact keys, expired contact, extra recipient and carrier drift rejected',()=>{
 const f=fixture();
 for(const change of [
  g=>{g.cfg.pqMode.deviceId=g.peer.deviceId;},
  g=>{g.trust.peer.address=g.self.address;},
  g=>{g.contacts[0].mlKemEncryptionSpki=g.self.contact.mlKemEncryptionSpki;},
  g=>{g.contacts[0].classicalEncryptionSpki=g.self.contact.classicalEncryptionSpki;},
  g=>{g.contacts[0].expires=now-1;},
  g=>{g.contacts.push(g.self.contact);},
  g=>{g.carrier.role='relay';},
  g=>{g.carrier.httpPort=49904;},
  g=>{g.carrier.secretHex=g.carrier.epochHex;},
  g=>{g.carrier.queueDir='C:\\Other\\queue';},
  g=>{g.cfg.windowsScattering.endpoint='https://example.com/';}
 ]){const g=structuredClone(f);change(g);assert.throws(()=>verify(g));}
});
function mocks(f,{trustBytes=Buffer.from(JSON.stringify(f.trust)),liveContact,broken=false}={}){
 const trustFile='C:\\QuanticLab\\trust-approved.json';
 const files=new Map([
  [win32.join(dir,'desktop.json'),Buffer.from(JSON.stringify(f.cfg))],
  [win32.join(dir,'contacts.json'),Buffer.from(JSON.stringify(f.contacts))],
  [win32.join(carrierDir,'scattering.json'),Buffer.from(JSON.stringify(f.carrier))]
 ]);
 let sources=0,loads=0;
 const deps={
  inspect:async p=>{assert.equal(p,trustFile);return {isFile:()=>true,isSymbolicLink:()=>false,size:trustBytes.length};},
  readTrust:async p=>{assert.equal(p,trustFile);return Buffer.from(trustBytes);},
  storageFactory:async({binary:bin,binarySha256:pin,dir:d})=>{
   assert.equal(bin,binary);assert.equal(pin,binarySha256);
   assert.ok([dir,carrierDir].includes(d));
   return {read:async p=>{loads++;assert.ok(files.has(p));return Buffer.from(files.get(p));}};
  },
  peerSourceFactory:async (_,opts)=>{
   assert.equal(typeof opts.read,'function');sources++;
   return async(address,deviceId)=>{
    if(broken)throw Error('Authority quorum unavailable');
    const who=address===f.self.address?f.self:f.peer;
    assert.equal(deviceId,who.deviceId);
    return {contact:liveContact??who.contact,checkpoint:{rootPin:who.rootPin,pqRootPin:who.pqRootPin}};
   };
  }
 };
 return {deps,args:{binary,binarySha256,dir,carrierDir,trustFile,trustSha256:hash(trustBytes)},counters:()=>({loads,sources})};
}
test('trusted on-disk file digest required before reading sensitive configs; offline report never claims live attestation',async()=>{
 const f=fixture(),m=mocks(f);
 const result=await runWindowsTwoHostReadiness({...m.args,live:false},m.deps);
 assert.equal(result.status,'offline-public-anchors-verified');
 assert.equal(m.counters().sources,0);
 assert.equal(m.counters().loads,3);
 const wrong=mocks(f);
 await assert.rejects(runWindowsTwoHostReadiness({...wrong.args,trustSha256:'0'.repeat(64)},wrong.deps));
 assert.equal(wrong.counters().loads,0);
 const swapped=mocks(f,{trustBytes:Buffer.from(JSON.stringify({...f.trust,authorities:[]}))});
 await assert.rejects(runWindowsTwoHostReadiness({...swapped.args,live:true},swapped.deps));
 assert.equal(swapped.counters().loads,0);
});
test('only fresh signed 3-of-4 authority source upgrades readiness; untrusted contact or outage fails closed',async()=>{
 const f=fixture(),m=mocks(f);
 const result=await runWindowsTwoHostReadiness({...m.args,live:true},m.deps);
 assert.equal(result.status,'fresh-mtls-3-of-4-quorum-and-contact-verified');
 assert.equal(result.authorityQuorumVerified,true);assert.equal(result.remoteTransportVerified,false);
 assert.equal(m.counters().sources,1);
 const off=mocks(f,{broken:true});
 await assert.rejects(runWindowsTwoHostReadiness({...off.args,live:true},off.deps));
 const tampered=mocks(f,{liveContact:{...f.peer.contact,mlDsaSigningSpki:f.self.contact.mlDsaSigningSpki}});
 await assert.rejects(runWindowsTwoHostReadiness({...tampered.args,live:true},tampered.deps));
});
