import {createNativeMailboxClient} from '../desktop/native-mailbox-client.mjs';
import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync,sign,randomBytes,diffieHellman,encapsulate,decapsulate,hkdfSync,createCipheriv,createDecipheriv,createPublicKey} from 'node:crypto';
import {canonicalManifestText} from '../lib/quantic/manifest-core.mjs';
import {canonicalCryptoProfileText} from '../lib/quantic/crypto-profile-core.mjs';
import {bindNativeContact,verifyNativeWire,nativeSenderTranscript} from '../lib/quantic/native-identity-bridge.mjs';
import {hasUnsupportedNativeFields} from '../lib/quantic/legacy-native-boundary.mjs';
const sha=x=>createHash('sha256').update(x).digest('hex');
const pk=k=>k.publicKey.export({format:'jwk'});
const spki=k=>k.publicKey.export({type:'spki',format:'der'});
const ec=()=>generateKeyPairSync('ec',{namedCurve:'prime256v1'});
const sig=(k,t)=>sign('sha256',Buffer.from(t),{key:k.privateKey,dsaEncoding:'ieee-p1363'});
const fp=j=>sha('P-256:'+j.x+':'+j.y).slice(0,32);
const now=Date.now(),issuedAt=new Date(now).toISOString();
function fixture(handle){
 const owner=ec(),enc=ec(),ds=ec(),root=generateKeyPairSync('ml-dsa-65'),kem=generateKeyPairSync('ml-kem-768'),dsa=generateKeyPairSync('ml-dsa-65');
 const address=handle+'~'+fp(pk(owner))+'@quantic',deviceId='d-'+fp(pk(enc));
 const p={version:1,sequence:1,canonicalAddress:address,handle,fingerprint:fp(pk(owner)),identityPublicKey:pk(enc),identitySigningPublicKey:pk(owner),devices:[{kind:'root',label:handle+' root',deviceId,publicKey:pk(enc),deviceSigningPublicKey:pk(ds),issuedAt}],revocations:[],issuedAt};
 const manifest={format:'quantic-identity-manifest',version:1,payload:p,signature:sig(owner,canonicalManifestText(p)).toString('base64')};
 const q={version:2,sequence:1,canonicalAddress:address,identitySigningPublicKey:pk(owner),identityManifestSequence:1,policy:'hybrid-required',identityMlDsaAlgorithm:'ML-DSA-65',identityMlDsaPublicKeySpki:spki(root).toString('base64url'),devices:[{deviceId,mlKemAlgorithm:'ML-KEM-768',mlKemPublicKeySpki:spki(kem).toString('base64url'),mlDsaAlgorithm:'ML-DSA-65',mlDsaPublicKeySpki:spki(dsa).toString('base64url')}],issuedAt};
 const raw=canonicalCryptoProfileText(q);
 const profile={format:'quantic-crypto-profile',version:2,payload:q,signatures:{p256:sig(owner,raw).toString('base64'),mlDsa65Self:sign(null,Buffer.from(raw),root.privateKey).toString('base64url')}};
 const checkpoint={address,deviceId,rootPin:sha(spki(owner)),pqRootPin:sha(spki(root)),manifestSequence:1,profileSequence:1,manifestDigest:sha(canonicalManifestText(p)),profileDigest:sha(raw),expires:now+20000};
 return {bundle:{manifest,profile},checkpoint,ds,dsa,owner,enc,kem};
}
test('bind current signed manifest/profile to native contact and verify native transcript',()=>{
 const a=fixture('alice'),b=fixture('bobby');
 const contact=bindNativeContact(a.bundle,a.checkpoint,now);
 assert.equal(contact.classicalSigningSpki,spki(a.ds).toString('base64'));
 assert.equal(contact.mlDsaSigningSpki,spki(a.dsa).toString('base64'));
 const context={clientMessageId:'native-bridge-0001',from:a.checkpoint.address,fromDeviceId:a.checkpoint.deviceId,to:b.checkpoint.address,toDeviceId:b.checkpoint.deviceId};
 const envelope={cryptoSuite:'QNT-HYB-P256-MLKEM768-HKDFSHA256-AES256GCM-1',keyMode:'hybrid-static-fallback',classicalEphemeralPublicKey:pk(ec()),pqKemCiphertext:randomBytes(1088).toString('base64url'),iv:randomBytes(12).toString('base64url'),ciphertext:randomBytes(32).toString('base64url')};
 const raw=nativeSenderTranscript(context,envelope);
 const record={format:'quantic-native-mail',version:1,context,envelope,senderAuth:{classicalSignature:sig(a.ds,raw).toString('base64url'),pqSignature:sign(null,raw,a.dsa.privateKey).toString('base64url')}};
 const run=(r=record,ac=a.checkpoint,bc=b.checkpoint)=>verifyNativeWire(r,a.bundle,ac,b.bundle,bc,now);
 assert.equal(run().liveDeliveryAuthorized,false);
 for(const c of [{...a.checkpoint,pqRootPin:'0'.repeat(64)},{...a.checkpoint,rootPin:'0'.repeat(64)},{...a.checkpoint,manifestSequence:2},{...a.checkpoint,profileSequence:2},{...a.checkpoint,profileDigest:'0'.repeat(64)},{...a.checkpoint,expires:now},{...a.checkpoint,expires:now+31000}])assert.throws(()=>run(record,c));
 assert.throws(()=>run(record,a.checkpoint,{...b.checkpoint,deviceId:a.checkpoint.deviceId}));
 for(const f of ['classicalSignature','pqSignature']){
  const v=Buffer.from(record.senderAuth[f],'base64url');v[0]^=1;
  assert.throws(()=>run({...record,senderAuth:{...record.senderAuth,[f]:v.toString('base64url')}}));
 }
 assert.throws(()=>run({...record,envelope:{...envelope,ciphertext:randomBytes(32).toString('base64url')}}));
 assert.throws(()=>run({...record,context:{...context,toDeviceId:a.checkpoint.deviceId}}));
 const m=structuredClone(a.bundle.manifest);m.payload.devices[0].deviceSigningPublicKey=pk(ec());
 assert.throws(()=>bindNativeContact({...a.bundle,manifest:m},a.checkpoint,now));
});
test('legacy routes reject fields that would silently discard cryptographic semantics',()=>{
 assert.equal(hasUnsupportedNativeFields({from:'a',ciphertext:'x',iv:'y',ephemeralPublicKey:{}}),false);
 for(const k of ['senderAuth','pqEnvelope','cryptoSuite','keyMode','signatures','context','version','preKeyId'])assert.equal(hasUnsupportedNativeFields({[k]:null}),true);
});

import {issueCheckpoint,verifyCheckpointQuorum} from '../lib/quantic/native-checkpoint-authority.mjs';
test('independent authority quorum reads durable schema, pins both roots and refuses stale or conflicting votes',()=>{
 const a=fixture('authorityalice');
 const state={format:'quantic-relay-state',version:3,savedAt:new Date(now).toISOString(),manifests:[[a.checkpoint.address,a.bundle.manifest]],cryptoProfiles:[[a.checkpoint.address,a.bundle.profile]]};
 const policy=[{...a.checkpoint,active:true}];
 const request={address:a.checkpoint.address,deviceId:a.checkpoint.deviceId,nonce:randomBytes(32).toString('hex'),expires:now+10000};
 const keys=Array.from({length:4},()=>generateKeyPairSync('ed25519'));
 const trusted=keys.map(k=>({pin:sha(spki(k)),publicKey:spki(k).toString('base64url')}));
 const vote=k=>issueCheckpoint({state,policy,request,privateKey:k.privateKey,now});
 const votes=keys.map(k=>vote(k).attestation);
 const cp=verifyCheckpointQuorum(votes.slice(0,3),trusted,request,now);
 assert.equal(bindNativeContact(a.bundle,cp,now).deviceId,a.checkpoint.deviceId);
 assert.throws(()=>verifyCheckpointQuorum(votes.slice(0,2),trusted,request,now));
 assert.throws(()=>verifyCheckpointQuorum([votes[0],votes[0],votes[1]],trusted,request,now));
 assert.throws(()=>verifyCheckpointQuorum(votes,[trusted[0],trusted[0],trusted[1],trusted[2]],request,now));
 assert.throws(()=>verifyCheckpointQuorum(votes,trusted,{...request,nonce:'0'.repeat(64)},now));
 assert.throws(()=>verifyCheckpointQuorum(votes,trusted,request,request.expires));
 const bad=structuredClone(votes);bad[0].payload.profileDigest='f'.repeat(64);bad[1].payload.manifestSequence=2;
 assert.throws(()=>verifyCheckpointQuorum(bad,trusted,request,now));
 const issue=(s=state,p=policy)=>issueCheckpoint({state:s,policy:p,request,privateKey:keys[0].privateKey,now});
 for(const s of [{...state,savedAt:new Date(now-30000).toISOString()},{...state,manifests:[]},{...state,cryptoProfiles:[]}])assert.throws(()=>issue(s));
 assert.throws(()=>issue(state,[{...policy[0],active:false}]));
 assert.throws(()=>issue(state,[{...policy[0],profileSequence:2}]));
 assert.throws(()=>issue(state,[{...policy[0],pqRootPin:'0'.repeat(64)}]));
});

import {mkdtemp,readFile,rm,open,mkdir} from 'node:fs/promises';
import {sealReceipt,openReceipt,syncReceiptDirectory} from '../desktop/native-receipt-store.mjs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {execFileSync} from 'node:child_process';
import {X509Certificate} from 'node:crypto';
import {startNativeCheckpointAuthority} from '../standalone-relay/native-checkpoint-server.mjs';
import {createAttestedPeerSource} from '../desktop/native-attested-peer.mjs';
test('four pinned mTLS authorities deliver real signed checkpoints and refuse two votes',async()=>{
 const dir=await mkdtemp(join(tmpdir(),'quantic-authority-'));
 const services=[];
 try{
  const openssl=(...args)=>execFileSync('openssl',args,{cwd:dir,stdio:'ignore'});
  openssl('req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:prime256v1','-nodes','-keyout','ca.key','-out','ca.crt','-subj','/CN=Quantic test CA','-days','1','-addext','basicConstraints=critical,CA:TRUE');
  for(const name of ['client','w0','w1','w2','w3']){
   openssl('req','-new','-newkey','ec','-pkeyopt','ec_paramgen_curve:prime256v1','-nodes','-keyout',name+'.key','-out',name+'.csr','-subj','/CN='+name,'-addext','subjectAltName=IP:127.0.0.1');
   openssl('x509','-req','-in',name+'.csr','-CA','ca.crt','-CAkey','ca.key','-CAcreateserial','-out',name+'.crt','-days','1','-copy_extensions','copy');
  }
  const a=fixture('transportalice');
  const state={format:'quantic-relay-state',version:3,savedAt:new Date().toISOString(),manifests:[[a.checkpoint.address,a.bundle.manifest]],cryptoProfiles:[[a.checkpoint.address,a.bundle.profile]]};
  const policy=[{...a.checkpoint,active:true}];
  const ca=await readFile(join(dir,'ca.crt')),clientPin=sha(new X509Certificate(await readFile(join(dir,'client.crt'))).raw);
  const authorities=[];
  for(let i=0;i<4;i++){
   const k=generateKeyPairSync('ed25519'),name='w'+i,cert=await readFile(join(dir,name+'.crt'));
   const service=await startNativeCheckpointAuthority({privateKey:k.privateKey,clientPins:[clientPin],tls:{ca,cert,key:await readFile(join(dir,name+'.key'))},load:async()=>({state,policy})});
   services.push(service);
   authorities.push({url:'https://127.0.0.1:'+service.port+'/native-checkpoint',pin:sha(spki(k)),publicKey:spki(k).toString('base64url'),tlsPin:sha(new X509Certificate(cert).raw)});
  }
  const source=await createAttestedPeerSource({authorities,caFile:join(dir,'ca.crt'),clientCertFile:join(dir,'client.crt'),clientKeyFile:join(dir,'client.key')});
  assert.equal((await source(a.checkpoint.address,a.checkpoint.deviceId)).contact.deviceId,a.checkpoint.deviceId);
  await services.pop().close();
  assert.equal((await source(a.checkpoint.address,a.checkpoint.deviceId)).contact.deviceId,a.checkpoint.deviceId);
  await services.pop().close();
  await assert.rejects(source(a.checkpoint.address,a.checkpoint.deviceId));
 }finally{await Promise.all(services.map(s=>s.close()));await rm(dir,{recursive:true,force:true});}
});

import {startRelayServer} from '../standalone-relay/server.ts';
import {createIdentityChallenge,registerIdentity} from '../lib/quantic/relay.ts';
import {nativeRecordDigest} from '../lib/quantic/native-mailbox.mjs';
import {startNativeScatteringLink} from './helpers/native-scattering-link.mjs';
const scatteringBinary=process.env.QUANTIC_INTEGRATED_SCATTERING_BINARY;
test('integrated native relay with four real mTLS authorities, bidirectional hybrid ciphertext, durable receipts, exact retry, ack and restart'+(scatteringBinary?' via two independent native UDP links':''),{timeout:180000},async()=>{
 const dir=await mkdtemp(join(tmpdir(),'quantic-native-mailbox-'));
 const a=fixture('queuealice'),b=fixture('queuebob');
 const fixtures=[a,b],services=[];
 let source,relay,relayPort=0;const links=new Map();
 const policy=fixtures.map(f=>({...f.checkpoint,active:true}));
 // Distinct keys and actual mTLS transport. The test supplies fresh fixture
 // snapshots, not production policy updates or independent physical hosts.
 const state=()=>({format:'quantic-relay-state',version:3,savedAt:new Date().toISOString(),manifests:fixtures.map(f=>[f.checkpoint.address,f.bundle.manifest]),cryptoProfiles:fixtures.map(f=>[f.checkpoint.address,f.bundle.profile])});
 async function setupAuthorities(){
  const openssl=(...args)=>execFileSync('openssl',args,{cwd:dir,stdio:'ignore'});
  openssl('req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:prime256v1','-nodes','-keyout','ca.key','-out','ca.crt','-subj','/CN=Quantic integrated test CA','-days','1','-addext','basicConstraints=critical,CA:TRUE');
  for(const name of ['client','w0','w1','w2','w3']){
   openssl('req','-new','-newkey','ec','-pkeyopt','ec_paramgen_curve:prime256v1','-nodes','-keyout',name+'.key','-out',name+'.csr','-subj','/CN='+name,'-addext','subjectAltName=IP:127.0.0.1');
   openssl('x509','-req','-in',name+'.csr','-CA','ca.crt','-CAkey','ca.key','-CAcreateserial','-out',name+'.crt','-days','1','-copy_extensions','copy');
  }
  const ca=await readFile(join(dir,'ca.crt')),clientPin=sha(new X509Certificate(await readFile(join(dir,'client.crt'))).raw),authorities=[];
  for(let i=0;i<4;i++){
   const k=generateKeyPairSync('ed25519'),name='w'+i,cert=await readFile(join(dir,name+'.crt'));
   const service=await startNativeCheckpointAuthority({privateKey:k.privateKey,clientPins:[clientPin],tls:{ca,cert,key:await readFile(join(dir,name+'.key'))},load:async()=>({state:state(),policy})});
   services.push(service);authorities.push({url:'https://127.0.0.1:'+service.port+'/native-checkpoint',pin:sha(spki(k)),publicKey:spki(k).toString('base64url'),tlsPin:sha(new X509Certificate(cert).raw)});
  }
  source=await createAttestedPeerSource({authorities,caFile:join(dir,'ca.crt'),clientCertFile:join(dir,'client.crt'),clientKeyFile:join(dir,'client.key')});
 }
 const start=()=>startRelayServer({host:'127.0.0.1',port:relayPort,dataDir:dir,nativePeerSource:source});
 const endpoint=f=>{if(scatteringBinary){const link=links.get(f);assert.ok(link,'No direct HTTP fallback');return link.url;}return relay.url;};
 const authToken=f=>sha('synthetic-token-'+f.checkpoint.address);
 function register(f){
  const p=f.bundle.manifest.payload;
  const input={handle:p.canonicalAddress,publicKey:p.identityPublicKey,signingPublicKey:p.identitySigningPublicKey};
  const c=createIdentityChallenge(input);
  const r=registerIdentity({...input,deviceId:f.checkpoint.deviceId,authToken:authToken(f),challenge:c.challenge,signature:sig(f.owner,c.challenge).toString('base64')});
  assert.equal(r.canonicalAddress,f.checkpoint.address);assert.equal(r.rootDeviceId,f.checkpoint.deviceId);
 }
 const suite='QNT-HYB-P256-MLKEM768-HKDFSHA256-AES256GCM-1';
 const plaintext=Buffer.from(JSON.stringify({subject:'Quantic integrated test',body:'encrypted mail round trip'}));
 function contextText(c){return ['quantic-hybrid-envelope-context-v1',suite,c.clientMessageId,c.from,c.fromDeviceId,c.to,c.toDeviceId].join('\n');}
 function symmetric(c,z,pq){
  const t=contextText(c),salt=createHash('sha256').update('quantic-hybrid-kdf-salt-v1\n'+t).digest();
  return Buffer.from(hkdfSync('sha256',Buffer.concat([z,pq]),salt,Buffer.from(t),32));
 }
 function makeRecord(sender=a,recipient=b,id='native-durable-0001',message=plaintext){
  const context={clientMessageId:id,from:sender.checkpoint.address,fromDeviceId:sender.checkpoint.deviceId,to:recipient.checkpoint.address,toDeviceId:recipient.checkpoint.deviceId};
  const eph=ec(),z=diffieHellman({privateKey:eph.privateKey,publicKey:recipient.enc.publicKey}),kem=encapsulate(recipient.kem.publicKey),key=symmetric(context,z,kem.sharedKey),iv=randomBytes(12);
  const g=createCipheriv('aes-256-gcm',key,iv);g.setAAD(Buffer.from(contextText(context)+'\nquantic-aes-gcm-aad-v1'));
  const ciphertext=Buffer.concat([g.update(message),g.final(),g.getAuthTag()]);
  const j=pk(eph);
  const envelope={cryptoSuite:suite,keyMode:'hybrid-static-fallback',classicalEphemeralPublicKey:{kty:j.kty,crv:j.crv,x:j.x,y:j.y},pqKemCiphertext:Buffer.from(kem.ciphertext).toString('base64url'),iv:iv.toString('base64url'),ciphertext:ciphertext.toString('base64url')};
  const raw=nativeSenderTranscript(context,envelope);
  z.fill(0);kem.sharedKey.fill(0);key.fill(0);
  return {format:'quantic-native-mail',version:1,context,envelope,senderAuth:{classicalSignature:sig(sender.ds,raw).toString('base64url'),pqSignature:sign(null,raw,sender.dsa.privateKey).toString('base64url')}};
 }
 function decryptRecord(record,recipient=b){
  const e=record.envelope,c=record.context,key=symmetric(c,diffieHellman({privateKey:recipient.enc.privateKey,publicKey:createPublicKey({key:e.classicalEphemeralPublicKey,format:'jwk'})}),decapsulate(recipient.kem.privateKey,Buffer.from(e.pqKemCiphertext,'base64url')));
  const ciphertext=Buffer.from(e.ciphertext,'base64url'),g=createDecipheriv('aes-256-gcm',key,Buffer.from(e.iv,'base64url'));
  g.setAAD(Buffer.from(contextText(c)+'\nquantic-aes-gcm-aad-v1'));g.setAuthTag(ciphertext.subarray(-16));
  try{return Buffer.concat([g.update(ciphertext.subarray(0,-16)),g.final()]);}finally{key.fill(0);}
 }
 const target=f=>({address:f.checkpoint.address,deviceId:f.checkpoint.deviceId});
 const post=async(op,body,f)=>{
  const res=await fetch(new URL('/api/quantic/native/v1/'+op,endpoint(f)),{method:'POST',headers:{'Content-Type':'application/json',Authorization:'Bearer '+authToken(f)},body:JSON.stringify(body)});
  return [res.status,await res.json()];
 };
 try{
  await setupAuthorities();relay=await start();register(a);register(b);
  if(scatteringBinary){
   relayPort=Number(new URL(relay.url).port);assert.ok(relayPort>0);
   for(const [idx,f] of fixtures.entries())links.set(f,await startNativeScatteringLink({dir:join(dir,'carrier-'+idx),binary:scatteringBinary,relayPort}));
  }
  const r=makeRecord(),changed=makeRecord();
  assert.notEqual((await post('send',r,b))[0],202);
  const [code,saved]=await post('send',r,a);assert.equal(code,202);assert.equal(saved.digest,nativeRecordDigest(r));assert.equal(saved.duplicate,false);
  await relay.close();relay=undefined;relay=await start();
  const client=createNativeMailboxClient({endpoint:endpoint(a),address:a.checkpoint.address,deviceId:a.checkpoint.deviceId,token:authToken(a)});
  const retry=await client.send(r);assert.equal(retry.id,saved.id);assert.equal(retry.duplicate,true);
  assert.equal((await post('send',changed,a))[0],409);
  const [pullCode,pull]=await post('pull',target(b),b);assert.equal(pullCode,200);assert.deepEqual(pull.item.record,r);assert.deepEqual(decryptRecord(pull.item.record),plaintext);
  const ack={...target(b),id:saved.id,digest:saved.digest};
  assert.notEqual((await post('ack',ack,a))[0],200);
  assert.equal((await post('ack',{...ack,digest:'0'.repeat(64)},b))[0],409);
  const receiptDir=join(dir,'recipient-receipts');await mkdir(receiptDir,{mode:0o700});
  const receiptKeys=new Map([[a,randomBytes(32)],[b,randomBytes(32)]]);
  async function saveReceipt(recipient,item,expected){
   const key=receiptKeys.get(recipient),scope=target(recipient);
   const raw=decryptRecord(item.record,recipient);
   assert.deepEqual(raw,expected);
   const payload=JSON.parse(raw.toString('utf8'));raw.fill(0);
   const sealed=sealReceipt(key,scope,item,payload);
   const path=join(receiptDir,item.id+'.json');
   const bytes=Buffer.from(JSON.stringify(sealed));
   assert.equal(bytes.includes(Buffer.from(payload.body)),false);
   const fd=await open(path,'wx',0o600);
   try{await fd.writeFile(bytes);await fd.sync();}finally{await fd.close();}
   await syncReceiptDirectory(path);
   const persisted=JSON.parse(await readFile(path,'utf8'));
   assert.deepEqual(openReceipt(key,scope,persisted),{id:item.id,digest:item.digest,payload});
   assert.throws(()=>openReceipt(receiptKeys.get(recipient===a?b:a),scope,persisted));
   assert.throws(()=>openReceipt(key,scope,{...persisted,digest:'0'.repeat(64)}));
   return {path,payload};
  }
  const firstReceipt=await saveReceipt(b,pull.item,plaintext);
  assert.equal((await post('ack',ack,b))[0],200);
  await relay.close();relay=undefined;relay=await start();
  assert.equal((await post('pull',target(b),b))[1].item,null);
  assert.deepEqual((await post('recover',ack,b))[1].item.record,r);
  const [lastCode,last]=await post('send',r,a);assert.equal(lastCode,202);assert.equal(last.status,'acknowledged');assert.equal(last.id,saved.id);
  assert.equal((await post('send',changed,a))[0],409);
  // Reply B -> A uses an independent message ID and the other recipient keys.
  const replyBody=Buffer.from(JSON.stringify({subject:'Reply',body:'bidirectional encrypted response'}));
  const reply=makeRecord(b,a,'native-durable-reply-0001',replyBody);
  const bob=createNativeMailboxClient({endpoint:endpoint(b),...target(b),token:authToken(b)});
  const deposited=await bob.send(reply);
  assert.equal(deposited.status,'queued');assert.equal(deposited.digest,nativeRecordDigest(reply));
  await relay.close();relay=undefined;relay=await start();
  const incoming=await client.pull();assert.deepEqual(incoming.record,reply);
  assert.equal(incoming.id,deposited.id);
  assert.throws(()=>decryptRecord(incoming.record,b));
  const secondReceipt=await saveReceipt(a,incoming,replyBody);
  await client.ack(incoming.id,incoming.digest);
  await relay.close();relay=undefined;relay=await start();
  assert.equal(await client.pull(),null);
  assert.deepEqual((await client.recover(incoming.id,incoming.digest)).record,reply);
  for(const [recipient,savedReceipt] of [[a,secondReceipt],[b,firstReceipt]]){
   const stored=JSON.parse(await readFile(savedReceipt.path,'utf8'));
   assert.deepEqual(openReceipt(receiptKeys.get(recipient),target(recipient),stored).payload,savedReceipt.payload);
  }
  for(const key of receiptKeys.values())key.fill(0);
  policy[1].active=false;
  assert.notEqual((await post('send',r,a))[0],202);
  assert.notEqual((await post('pull',target(b),b))[0],200);
  if(scatteringBinary){await links.get(a).close();await assert.rejects(post('send',r,a));}
 }finally{await Promise.all([...links.values()].map(x=>x.close()));if(relay)await relay.close();await Promise.all(services.map(x=>x.close()));await rm(dir,{recursive:true,force:true});}
});

import {checkMigrationContinuity} from '../lib/quantic/migration-continuity.mjs';
test('migration continuity requires both devices in the same newer signed hybrid snapshot without replacing old keys',async()=>{
 const a=fixture('migrationalice'),n=fixture('newfixture'),old=structuredClone(a.bundle.manifest);
 const p={...old.payload,sequence:2,devices:[...old.payload.devices,{...n.bundle.manifest.payload.devices[0],kind:'linked'}]};
 const manifest={...old,payload:p,signature:sig(a.owner,canonicalManifestText(p)).toString('base64')};
 const q={...a.bundle.profile.payload,sequence:2,identityManifestSequence:2,devices:[...a.bundle.profile.payload.devices,...n.bundle.profile.payload.devices]};
 // New PQ root independently pinned; historical snapshot includes classical manifest only.
 const rootKey=generateKeyPairSync('ml-dsa-65');
 // A distinct test root is independently pinned below; the original archive has only the classical manifest.
 q.identityMlDsaPublicKeySpki=spki(rootKey).toString('base64url');
 const profileText=canonicalCryptoProfileText(q);
 const pqSig=sign(null,Buffer.from(profileText),rootKey.privateKey).toString('base64url');
 const profile={format:'quantic-crypto-profile',version:2,payload:q,signatures:{p256:sig(a.owner,profileText).toString('base64'),mlDsa65Self:pqSig}};
 const base={...a.checkpoint,pqRootPin:sha(spki(rootKey)),manifestSequence:2,profileSequence:2,manifestDigest:sha(canonicalManifestText(p)),profileDigest:sha(profileText)};
 const witnesses=Array.from({length:4},()=>generateKeyPairSync('ed25519'));
 const trusted=witnesses.map(k=>({pin:sha(spki(k)),publicKey:spki(k).toString('base64url')}));
 const newDeviceId=n.checkpoint.deviceId,oldDeviceId=a.checkpoint.deviceId;
 const peerSource=async(address,deviceId)=>{
  const t=Date.now(),request={address,deviceId,nonce:randomBytes(32).toString('hex'),expires:t+10000};
  const state={format:'quantic-relay-state',version:3,savedAt:new Date(t).toISOString(),manifests:[[address,manifest]],cryptoProfiles:[[address,profile]]};
  const policy=[{...base,deviceId:oldDeviceId,active:true},{...base,deviceId:newDeviceId,active:true}];
  const votes=witnesses.map(k=>issueCheckpoint({state,policy,request,privateKey:k.privateKey,now:t}));
  return {bundle:votes[0].bundle,checkpoint:verifyCheckpointQuorum(votes.map(v=>v.attestation),trusted,request,t)};
 };
 const opts={historicalManifest:old,address:a.checkpoint.address,oldDeviceId,newDeviceId,rootPin:a.checkpoint.rootPin,pqRootPin:base.pqRootPin,newDevicePins:[n.ds,n.enc,n.kem,n.dsa].map(k=>sha(spki(k))),peerSource};
 const result=await checkMigrationContinuity(opts);
 assert.equal(result.previousDeviceActive,true);assert.equal(result.newDeviceAttested,true);assert.equal(result.liveRestoreAuthorized,false);assert.equal(result.legacyDeletionAuthorized,false);
 await assert.rejects(checkMigrationContinuity({...opts,newDevicePins:['f'.repeat(64),...opts.newDevicePins.slice(1)]}));
 await assert.rejects(checkMigrationContinuity({...opts,pqRootPin:'f'.repeat(64)}));
 await assert.rejects(checkMigrationContinuity({...opts,peerSource:async(address,id)=>id===newDeviceId?Promise.reject(Error('unavailable')):peerSource(address,id)}));
});
