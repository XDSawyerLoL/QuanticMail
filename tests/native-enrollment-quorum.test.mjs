import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,createHash,sign,createPublicKey,diffieHellman,decapsulate,encapsulate,hkdfSync,createDecipheriv,createCipheriv,randomBytes} from 'node:crypto';
import {mkdtemp,mkdir,writeFile,readFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {startNativeScatteringLink} from './helpers/native-scattering-link.mjs';
const carrierBinary=process.env.QUANTIC_ENROLLED_SCATTERING_BINARY?resolve(process.env.QUANTIC_ENROLLED_SCATTERING_BINARY):null;
import {createSignedAuthorityRenewalLab} from '../standalone-relay/native-authority-renewal-lab.mjs';
import {approveNativeAuthorityRenewalLab} from '../standalone-relay/native-authority-approval-lab.mjs';
import {canonicalManifestText} from '../lib/quantic/manifest-core.mjs';
import {canonicalCryptoProfileText} from '../lib/quantic/crypto-profile-core.mjs';
import {prepareNativePossessionChallenge} from '../desktop/native-enrollment-possession.mjs';
import {enrollmentRosterPin,verifyNativeEnrollmentQuorum,prepareQuorumEnrollmentPolicy,enrollmentVoteTranscript} from '../desktop/native-enrollment-quorum.mjs';
import {createEmptyRelayState} from '../lib/quantic/relay-state.ts';
import {makeNativeEnrollmentCredential,prepareNativeEnrollmentPublication} from '../lib/quantic/native-enrollment-registry.mjs';
import {startNativeMailboxOnly} from '../standalone-relay/native-mailbox-only.mjs';
import {nativeSenderTranscript} from '../lib/quantic/native-identity-bridge.mjs';
import {issueCheckpoint,verifyCheckpointQuorum} from '../lib/quantic/native-checkpoint-authority.mjs';
const hash=x=>createHash('sha256').update(x).digest('hex');
const ec=()=>generateKeyPairSync('ec',{namedCurve:'prime256v1'});
const jwk=k=>k.publicKey.export({format:'jwk'});
const der=k=>k.publicKey.export({format:'der',type:'spki'});
const fp=j=>hash('P-256:'+j.x+':'+j.y).slice(0,32);
const sig=(k,b)=>sign('sha256',b,{key:k.privateKey,dsaEncoding:'ieee-p1363'}).toString('base64');
const buf=x=>Buffer.from(JSON.stringify(x));
function fixture({sharedAuthority,clock=Date.now}={}){
 const now=clock(),stamp=new Date(now).toISOString(),owner=ec(),enc=ec(),signer=ec(),
 root=generateKeyPairSync('ml-dsa-65'),kem=generateKeyPairSync('ml-kem-768'),dsa=generateKeyPairSync('ml-dsa-65');
 const address='testquorum~'+fp(jwk(owner))+'@quantic',deviceId='d-'+fp(jwk(enc)),quorumPin='c'.repeat(64);
 const mp={version:1,sequence:1,canonicalAddress:address,handle:'testquorum',fingerprint:fp(jwk(owner)),
 identityPublicKey:jwk(enc),identitySigningPublicKey:jwk(owner),devices:[{deviceId,label:'Test device',publicKey:jwk(enc),deviceSigningPublicKey:jwk(signer),kind:'root',issuedAt:stamp}],revocations:[],issuedAt:stamp};
 const m=Buffer.from(canonicalManifestText(mp));
 const pp={version:2,sequence:1,canonicalAddress:address,identitySigningPublicKey:jwk(owner),identityManifestSequence:1,policy:'hybrid-required',identityMlDsaAlgorithm:'ML-DSA-65',
 identityMlDsaPublicKeySpki:der(root).toString('base64url'),devices:[{deviceId,mlKemAlgorithm:'ML-KEM-768',mlKemPublicKeySpki:der(kem).toString('base64url'),mlDsaAlgorithm:'ML-DSA-65',mlDsaPublicKeySpki:der(dsa).toString('base64url')}],issuedAt:stamp};
 const p=Buffer.from(canonicalCryptoProfileText(pp));
 const claim={format:'quantic-native-enrollment-claim-lab/v1',version:1,labOnly:true,status:'signed-claim-not-enrolled',remotelyEnrolled:false,mailAuthorized:false,address,deviceId,
 rootPin:hash(der(owner)),pqRootPin:hash(der(root)),signingPin:hash(der(signer)),encryptionPin:hash(der(enc)),kemPin:hash(der(kem)),dsaPin:hash(der(dsa)),manifestDigest:hash(m),profileDigest:hash(p),
 manifest:{format:'quantic-identity-manifest',version:1,payload:mp,signature:sig(owner,m)},
 profile:{format:'quantic-crypto-profile',version:2,payload:pp,signatures:{p256:sig(owner,p),mlDsa65Self:sign(null,p,root.privateKey).toString('base64url')}}};
 const controller=generateKeyPairSync('ed25519'),controllerPublic=der(controller).subarray(12).toString('base64url'),format='quantic-native-enrollment-request-lab/v1';
 const tr=buf([format,address,deviceId,claim.rootPin,claim.pqRootPin,claim.manifestDigest,claim.profileDigest,quorumPin,controllerPublic]);
 const request={format,quorumPin,controllerPublic,claim,ownerP256Signature:sig(owner,tr),ownerMlDsaSignature:sign(null,tr,root.privateKey).toString('base64url')};
 const authority=sharedAuthority??Array.from({length:4},()=>generateKeyPairSync('ed25519'));
 const trusted=authority.map(k=>({pin:hash(der(k)),publicKey:der(k).toString('base64url')}));
 const rosterPin=enrollmentRosterPin(trusted),opts={quorumPin,trusted,rosterPin,now};
 function prepare(i){return prepareNativePossessionChallenge(request,{quorumPin,trusted,rosterPin,authorityKey:authority[i].privateKey,expectedAuthorityPin:trusted[i].pin,clock:()=>now});}
 function respond(c){
  const e=c.envelope,id='enroll-'+c.nonce;
  const ctx=['quantic-hybrid-envelope-context-v1',e.cryptoSuite,id,address,deviceId,address,deviceId].join('\n');
  const z=diffieHellman({privateKey:enc.privateKey,publicKey:createPublicKey({key:e.classicalEphemeralPublicKey,format:'jwk'})});
  const shared=Buffer.concat([z,decapsulate(kem.privateKey,Buffer.from(e.pqKemCiphertext,'base64url'))]);
  const key=Buffer.from(hkdfSync('sha256',shared,Buffer.from(hash('quantic-hybrid-kdf-salt-v1\n'+ctx),'hex'),Buffer.from(ctx),32));
  const ct=Buffer.from(e.ciphertext,'base64url'),g=createDecipheriv('aes-256-gcm',key,Buffer.from(e.iv,'base64url'));
  g.setAAD(Buffer.from(ctx+'\nquantic-aes-gcm-aad-v1'));g.setAuthTag(ct.subarray(-16));
  const secret=Buffer.concat([g.update(ct.subarray(0,-16)),g.final()]);
  const challengeHash=hash(buf([c.format,c.authorityPin,c.quorumPin,c.address,c.deviceId,c.manifestDigest,c.profileDigest,c.nonce,String(c.expires),e.cryptoSuite,e.keyMode,e.classicalEphemeralPublicKey.kty,e.classicalEphemeralPublicKey.crv,e.classicalEphemeralPublicKey.x,e.classicalEphemeralPublicKey.y,e.pqKemCiphertext,e.iv,e.ciphertext]));
  const format='quantic-native-enrollment-possession-response-lab/v1',secretHash=hash(secret),raw=buf([format,challengeHash,secretHash]);
  secret.fill(0);key.fill(0);shared.fill(0);z.fill(0);
  return {format,challengeHash,secretHash,p256Signature:sig(signer,raw),mlDsaSignature:sign(null,raw,dsa.privateKey).toString('base64url')};
 }
 const votes=[0,1,2,3].map(i=>{const session=prepare(i);const result=session.verify(respond(session.challenge),{approved:true,approveEnrollment:true});return result.vote;});
 const state={format:'quantic-relay-state',version:3,savedAt:stamp,manifests:[[address,claim.manifest]],cryptoProfiles:[[address,claim.profile]]};
 return {now,request,opts,votes,authority,prepare,respond,state,controller,enc,signer,kem,dsa};
}
test('3 of 4 actual independently keyed device challenges authorize only a staged policy; current checkpoints require separately activated policy',()=>{
 const f=fixture(),{request,opts,votes,state,now}=f;
 assert.throws(()=>verifyNativeEnrollmentQuorum(request,votes.slice(0,2),opts));
 assert.throws(()=>verifyNativeEnrollmentQuorum(request,[votes[0],votes[0],votes[1]],opts));
 assert.throws(()=>verifyNativeEnrollmentQuorum(request,votes,{...opts,rosterPin:'0'.repeat(64)}));
 const r=verifyNativeEnrollmentQuorum(request,votes.slice(0,3),opts);
 assert.equal(r.approvals,3);assert.equal(r.policyCandidate.active,false);assert.equal(r.mailAuthorized,false);
 const bad=structuredClone(votes[2]);bad.payload.requestDigest='a'.repeat(64);
 assert.throws(()=>verifyNativeEnrollmentQuorum(request,[votes[0],votes[1],bad],opts));
 const forged=structuredClone(votes[2]);forged.payload.proofDigest=votes[0].payload.proofDigest;
 forged.signature=sign(null,enrollmentVoteTranscript(forged.payload),f.authority[2].privateKey).toString('base64url');
 assert.throws(()=>verifyNativeEnrollmentQuorum(request,[votes[0],votes[1],forged],opts));
 assert.throws(()=>verifyNativeEnrollmentQuorum(request,votes,{...opts,now:now+900000}));
 const s=f.prepare(0),proof=f.respond(s.challenge);
 assert.throws(()=>s.verify(proof,{approved:false,approveEnrollment:true}));assert.throws(()=>s.verify(proof,{approved:true,approveEnrollment:true}));
 const p=f.prepare(0);assert.equal(p.verify(f.respond(p.challenge),{approved:true}).vote,undefined);
 assert.throws(()=>prepareQuorumEnrollmentPolicy(request,votes,{...opts,state,previousPolicy:[],approved:false}));
 assert.throws(()=>prepareQuorumEnrollmentPolicy(request,votes,{...opts,state:{...state,savedAt:new Date(now-31000).toISOString()},previousPolicy:[],approved:true}));
 assert.throws(()=>prepareQuorumEnrollmentPolicy(request,votes,{...opts,state,previousPolicy:[r.policyCandidate],approved:true}));
 const prepared=prepareQuorumEnrollmentPolicy(request,votes.slice(0,3),{...opts,state,previousPolicy:[],approved:true});
 assert.equal(prepared.policy[0].active,true);assert.equal(prepared.remotelyEnrolled,false);
 const q={address:request.claim.address,deviceId:request.claim.deviceId,nonce:'1'.repeat(64),expires:now+14000};
 assert.throws(()=>issueCheckpoint({state,policy:[r.policyCandidate],request:q,privateKey:f.authority[0].privateKey,now}));
 const attestations=f.authority.slice(0,3).map(a=>issueCheckpoint({state,policy:prepared.policy,request:q,privateKey:a.privateKey,now}).attestation);
 assert.throws(()=>verifyCheckpointQuorum(attestations.slice(0,2),opts.trusted,q,now));
 assert.equal(verifyCheckpointQuorum(attestations,opts.trusted,q,now).address,q.address);
});

test('approved enrollment survives the real signed renewal and durable head of three separate authority directories',{skip:process.platform!=='linux',timeout:30000},async()=>{
 const f=fixture(),other=fixture(),root=await mkdtemp(join(tmpdir(),'qs-enrollment-renewal-'));
 try{
  const initialPolicy=[{...verifyNativeEnrollmentQuorum(other.request,other.votes,other.opts).policyCandidate,active:true}];
  const initialState=other.state;
  const state={...f.state,manifests:[...initialState.manifests,...f.state.manifests],cryptoProfiles:[...initialState.cryptoProfiles,...f.state.cryptoProfiles]};
  const before=verifyNativeEnrollmentQuorum(f.request,f.votes,f.opts);
  const prepared=prepareQuorumEnrollmentPolicy(f.request,f.votes.slice(0,3),{...f.opts,state,previousPolicy:initialPolicy,approved:true});
  assert.deepEqual(prepared.policy[0],initialPolicy[0]);
  const q={address:before.policyCandidate.address,deviceId:before.policyCandidate.deviceId,nonce:'a'.repeat(64),expires:f.now+14000};
  const attestations=[];
  for(let i=0;i<3;i++){
   const dir=join(root,'authority-'+i),keyFile=join(root,'renewal-'+i+'.pem');
   const renewal=generateKeyPairSync('ed25519');
   await mkdir(dir,{mode:0o700});await mkdir(join(dir,'renewals'),{mode:0o700});
   await writeFile(keyFile,renewal.privateKey.export({type:'pkcs8',format:'pem'}),{mode:0o600,flag:'wx'});
   const cfg={format:'quantic-native-authority-operator-lab/v2',labOnly:true,authorityId:'authority-'+i,port:0,
    pins:{statePin:hash(buf(initialState)),policyPin:hash(buf(initialPolicy)),signerPin:f.opts.trusted[i].pin},clientPins:[],
    renewalPublicKey:der(renewal).toString('base64url')};
   const configBytes=buf(cfg),configPin=hash(configBytes);
   await writeFile(join(dir,'operator.json'),configBytes,{mode:0o600,flag:'wx'});
   const args={directory:dir,authorityId:cfg.authorityId,configPin,initialStatePin:cfg.pins.statePin,initialPolicyPin:cfg.pins.policyPin,
    publicKey:cfg.renewalPublicKey,initialSnapshot:{state:initialState,policy:initialPolicy},now:()=>f.now};
   // The initial fixture predates or equals the candidate clock.
   args.now=()=>Math.max(f.now,other.now);
   let service=await createSignedAuthorityRenewalLab(args);
   assert.throws(()=>issueCheckpoint({state:initialState,policy:initialPolicy,request:q,privateKey:f.authority[i].privateKey,now:args.now()}));
   const folder=join(dir,'renewals','000001');
   await mkdir(folder,{mode:0o700});
   await writeFile(join(folder,'state.json'),buf(state),{mode:0o600,flag:'wx'});
   await writeFile(join(folder,'policy.json'),buf(prepared.policy),{mode:0o600,flag:'wx'});
   // Files alone do not activate an identity.
   assert.deepEqual((await service.load()).policy,initialPolicy);
   const previousHash=service.status().chainHash;
   await approveNativeAuthorityRenewalLab({directory:dir,configPin,operatorKeyFile:keyFile,sequence:1,previousHash,now:args.now()});
   const after=await service.load();
   assert.equal(after.policy.length,2);
   assert.equal(service.status().sequence,1);
   assert.equal(JSON.parse(await readFile(join(dir,'accepted-head.json'),'utf8')).sequence,1);
   // Reconstruct from disk instead of using the previous process state.
   service=await createSignedAuthorityRenewalLab(args);
   const restored=await service.load();
   assert.deepEqual(restored.policy,prepared.policy);
   attestations.push(issueCheckpoint({state:restored.state,policy:restored.policy,request:q,privateKey:f.authority[i].privateKey,now:args.now()}).attestation);
  }
  assert.throws(()=>verifyCheckpointQuorum(attestations.slice(0,2),f.opts.trusted,q,Math.max(f.now,other.now)));
  assert.equal(verifyCheckpointQuorum(attestations,f.opts.trusted,q,Math.max(f.now,other.now)).address,q.address);
 }finally{await rm(root,{recursive:true,force:true});}
});

test('native-only relay durably publishes two quorum-enrolled identities, refuses web and legacy auth, exchanges encrypted mail after live checkpoint approval'+(carrierBinary?' via two native UDP carriers':''),{skip:process.platform!=='linux',timeout:120000},async()=>{
 const a=fixture(),b=fixture({sharedAuthority:a.authority}),root=await mkdtemp(join(tmpdir(),'qs-native-enrolled-'));
 const options=f=>({...f.opts,approved:true});
 const ca=makeNativeEnrollmentCredential(a.request,a.votes,options(a),a.controller.privateKey);
 const cb=makeNativeEnrollmentCredential(b.request,b.votes,options(b),b.controller.privateKey);
 const enrollment=(f,c)=>({request:f.request,votes:f.votes,credential:c.credential,options:options(f)});
 assert.throws(()=>prepareNativeEnrollmentPublication(createEmptyRelayState(),a.request,a.votes.slice(0,2),ca.credential,options(a)));
 assert.throws(()=>prepareNativeEnrollmentPublication(createEmptyRelayState(),a.request,a.votes,{...ca.credential,tokenHash:'f'.repeat(64)},options(a)));
 assert.throws(()=>makeNativeEnrollmentCredential(a.request,a.votes,options(a),b.controller.privateKey));
 let service,policy=[],snapshot,relayPort=0,requireCarrier=false;const links=new Map();
 const source=async(address,deviceId)=>{
  const now=Date.now(),request={address,deviceId,nonce:randomBytes(32).toString('hex'),expires:now+14000};
  const results=a.authority.slice(0,3).map(k=>issueCheckpoint({state:snapshot,policy,request,privateKey:k.privateKey,now}));
  return {bundle:results[0].bundle,checkpoint:verifyCheckpointQuorum(results.map(r=>r.attestation),a.opts.trusted,request,now)};
 };
 async function start(e){service=await startNativeMailboxOnly({dataDir:root,port:relayPort,peerSource:source,enrollment:e});if(relayPort)assert.equal(service.port,relayPort);}
 async function stop(){if(service){await service.close();service=undefined;}}
 async function call(op,body,token,headers={}){
  const link=links.get(token);
  if(requireCarrier)assert.ok(link,'native carrier mandatory after enrollment; no direct fallback');
  const base=link?link.url:'http://127.0.0.1:'+service.port+'/';
  const r=await fetch(new URL('/api/quantic/'+op,base),{method:'POST',headers:{'Content-Type':'application/json',Authorization:'Bearer '+token,Connection:'close',...headers},body:JSON.stringify(body),signal:AbortSignal.timeout(30000)});
  return {status:r.status,body:await r.json()};
 }
 function scope(f){return {address:f.request.claim.address,deviceId:f.request.claim.deviceId};}
 try{
  const legacy=Buffer.from('legacy file left untouched');
  await writeFile(join(root,'relay-state.json'),legacy,{mode:0o600,flag:'wx'});
  await start(enrollment(a,ca));
  assert.deepEqual(await readFile(join(root,'relay-state.json')),legacy);
  await assert.rejects(startNativeMailboxOnly({dataDir:root,peerSource:source}));
  assert.equal(service.publication.status,'native-enrollment-persisted-pending-checkpoints');
  snapshot=await service.exportAuthoritySnapshot();
  assert.equal(snapshot.manifests.length,1);assert.equal(Object.hasOwn(snapshot,'nativeEnrollments'),false);
  assert.equal((await call('native/v1/pull',scope(a),ca.token)).status,403);
  assert.equal((await call('register',{},ca.token)).status,404);
  assert.equal((await call('native/v1/pull',scope(a),ca.token,{Origin:'https://invalid.example'})).status,403);
  await stop();
  await assert.rejects(startNativeMailboxOnly({dataDir:root,peerSource:source,enrollment:enrollment(a,ca)}));
  await start(enrollment(b,cb));
  snapshot=await service.exportAuthoritySnapshot();
  assert.equal(snapshot.manifests.length,2);
  assert.ok(!JSON.stringify(snapshot).includes(ca.credential.tokenHash));
  const persisted=JSON.parse(await readFile(join(root,'native-mailbox-state.json'),'utf8'));
  assert.equal(persisted.nativeEnrollments.length,2);assert.equal(persisted.identities.length,0);assert.equal(persisted.devices.length,0);
  assert.ok(!JSON.stringify(persisted).includes(ca.token));
  assert.ok(!JSON.stringify(persisted).includes(cb.token));
  for(const f of [a,b]){
   policy=prepareQuorumEnrollmentPolicy(f.request,f.votes,{...f.opts,now:Date.now(),state:snapshot,previousPolicy:policy,approved:true}).policy;
  }
  const transportRelay={signer:ec(),dsa:generateKeyPairSync('ml-dsa-65')};
  const sessionIdentity=f=>({local:{classical:f.signer.publicKey,pq:f.dsa.publicKey},privateKeys:{classical:f.signer.privateKey,pq:f.dsa.privateKey}});
  const sessionPeers=f=>{
   // Bind the client handshake keys to the enrolled signed profile.
   assert.equal(hash(der(f.signer)),f.request.claim.signingPin);
   assert.equal(hash(der(f.dsa)),f.request.claim.dsaPin);
   return [sessionIdentity(f),sessionIdentity(transportRelay)];
  };
  if(carrierBinary){
   relayPort=service.port;
   for(const [i,credential] of [ca,cb].entries()){
    const link=await startNativeScatteringLink({dir:join(root,'carrier-'+i),binary:carrierBinary,relayPort,sessionPeers:sessionPeers([a,b][i])});
    assert.equal(link.negotiated,true);links.set(credential.token,link);
   }
   assert.notEqual(links.get(ca.token).epochId,links.get(cb.token).epochId);
   requireCarrier=true;
  }
  assert.equal((await call('native/v1/pull',scope(a),cb.token)).status,403);
  assert.equal((await call('native/v1/pull',scope(a),ca.token)).status,200);
  // Real hybrid ciphertext and both sender signatures; no fabricated wire.
  const context={clientMessageId:'qs-native-enrollment-test-1',from:scope(a).address,fromDeviceId:scope(a).deviceId,to:scope(b).address,toDeviceId:scope(b).deviceId};
  const cryptoSuite='QNT-HYB-P256-MLKEM768-HKDFSHA256-AES256GCM-1';
  const ctx=['quantic-hybrid-envelope-context-v1',cryptoSuite,context.clientMessageId,context.from,context.fromDeviceId,context.to,context.toDeviceId].join('\n');
  const eph=ec(),z=diffieHellman({privateKey:eph.privateKey,publicKey:b.enc.publicKey}),kem=encapsulate(b.kem.publicKey);
  const shared=Buffer.concat([z,kem.sharedKey]),key=Buffer.from(hkdfSync('sha256',shared,Buffer.from(hash('quantic-hybrid-kdf-salt-v1\n'+ctx),'hex'),Buffer.from(ctx),32));
  const iv=randomBytes(12),g=createCipheriv('aes-256-gcm',key,iv);g.setAAD(Buffer.from(ctx+'\nquantic-aes-gcm-aad-v1'));
  const plain=Buffer.from('synthetic native enrollment mail');
  const ciphertext=Buffer.concat([g.update(plain),g.final(),g.getAuthTag()]);
  const envelope={cryptoSuite,keyMode:'hybrid-static-fallback',classicalEphemeralPublicKey:jwk(eph),pqKemCiphertext:Buffer.from(kem.ciphertext).toString('base64url'),iv:iv.toString('base64url'),ciphertext:ciphertext.toString('base64url')};
  const tr=nativeSenderTranscript(context,envelope);
  const record={format:'quantic-native-mail',version:1,context,envelope,senderAuth:{classicalSignature:sign('sha256',tr,{key:a.signer.privateKey,dsaEncoding:'ieee-p1363'}).toString('base64url'),pqSignature:sign(null,tr,a.dsa.privateKey).toString('base64url')}};
  const sent=await call('native/v1/send',record,ca.token);assert.equal(sent.status,202);
  await stop();await start();snapshot=await service.exportAuthoritySnapshot();
  const pulled=await call('native/v1/pull',scope(b),cb.token);assert.equal(pulled.status,200);
  const item=pulled.body.item;assert.equal(item.id,sent.body.id);assert.deepEqual(item.record,record);
  const e=item.record.envelope,zz=diffieHellman({privateKey:b.enc.privateKey,publicKey:createPublicKey({key:e.classicalEphemeralPublicKey,format:'jwk'})});
  const ss=Buffer.concat([zz,decapsulate(b.kem.privateKey,Buffer.from(e.pqKemCiphertext,'base64url'))]);
  const kk=Buffer.from(hkdfSync('sha256',ss,Buffer.from(hash('quantic-hybrid-kdf-salt-v1\n'+ctx),'hex'),Buffer.from(ctx),32)),ct=Buffer.from(e.ciphertext,'base64url');
  const dec=createDecipheriv('aes-256-gcm',kk,Buffer.from(e.iv,'base64url'));dec.setAAD(Buffer.from(ctx+'\nquantic-aes-gcm-aad-v1'));dec.setAuthTag(ct.subarray(-16));
  assert.deepEqual(Buffer.concat([dec.update(ct.subarray(0,-16)),dec.final()]),plain);
  for(const secret of [z,kem.sharedKey,shared,key,zz,ss,kk])secret.fill(0);
  assert.equal((await call('native/v1/ack',{...scope(b),id:item.id,digest:item.digest},cb.token)).status,200);
  assert.equal((await call('native/v1/pull',scope(b),cb.token)).body.item,null);
  await stop();await start();snapshot=await service.exportAuthoritySnapshot();
  const recovered=await call('native/v1/recover',{...scope(b),id:item.id,digest:item.digest},cb.token);
  assert.equal(recovered.status,200);assert.equal(recovered.body.item.id,item.id);assert.deepEqual(recovered.body.item.record,record);
  if(carrierBinary){
   const old=links.get(ca.token);await old.close();
   const fresh=await startNativeScatteringLink({dir:join(root,'carrier-replacement'),binary:carrierBinary,relayPort,sessionPeers:sessionPeers(a)});
   assert.equal(fresh.negotiated,true);links.set(ca.token,fresh);assert.notEqual(fresh.epochId,old.epochId);
   const retry=await call('native/v1/send',record,ca.token);
   assert.equal(retry.status,202);assert.equal(retry.body.id,item.id);assert.equal(retry.body.duplicate,true);assert.equal(retry.body.status,'acknowledged');
   assert.equal((await call('native/v1/pull',scope(b),cb.token)).body.item,null);
   await fresh.close();
   await assert.rejects(call('native/v1/send',record,ca.token));
   console.log('ENROLLED_NATIVE_UDP_EVIDENCE '+JSON.stringify({twoEnrolledIdentities:true,authenticatedHybridHandshake:true,deviceSigningPinsBound:true,bootstrapPreconfigured:true,preSharedBootstrapSecret:false,bootstrapFragmentLossRecovered:true,independentCarrierEpochs:true,hybridDecryption:true,relayRestart:true,exactRetry:true,noDuplicate:true,noDirectFallback:true,physicalHosts:1,releaseAuthorized:false}));
  }
  assert.deepEqual(await readFile(join(root,'relay-state.json')),legacy);
 }finally{await Promise.all([...links.values()].map(x=>x.close()));await stop();await rm(root,{recursive:true,force:true});}
});
