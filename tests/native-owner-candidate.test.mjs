import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync,randomBytes,createHmac,createPublicKey,diffieHellman,decapsulate,sign} from 'node:crypto';
import {issueNativePossessionChallenge} from '../lib/quantic/native-possession-challenge.mjs';
import {nativeOwnerAddress,prepareNativeIdentityCandidate} from '../lib/quantic/native-owner-candidate.mjs';
import {deviceIdForPublicKeyNode} from '../lib/quantic/manifest-node.mjs';
import {issueCheckpoint,verifyCheckpointQuorum} from '../lib/quantic/native-checkpoint-authority.mjs';
import {bindNativeContact} from '../lib/quantic/native-identity-bridge.mjs';
const sha=b=>createHash('sha256').update(b).digest('hex');
const spki=k=>k.export({type:'spki',format:'der'});
const ec=()=>generateKeyPairSync('ec',{namedCurve:'prime256v1'});
const point=k=>{const j=k.export({format:'jwk'});return Buffer.concat([Buffer.from([4]),Buffer.from(j.x,'base64url'),Buffer.from(j.y,'base64url')]).toString('base64url');};
function fixture(){
 const owner=ec(),root=generateKeyPairSync('ml-dsa-65'),s=ec(),e=ec(),kem=generateKeyPairSync('ml-kem-768'),dsa=generateKeyPairSync('ml-dsa-65');
 const handle='alice',now=Date.now(),address=nativeOwnerAddress(handle,owner.publicKey);
 const deviceId=deviceIdForPublicKeyNode(e.publicKey.export({format:'jwk'}),32);
 const expected={address,deviceId,rootPin:sha(spki(owner.publicKey)),pqRootPin:sha(spki(root.publicKey)),quorumPin:randomBytes(32).toString('hex'),signingPin:sha(spki(s.publicKey)),encryptionPin:sha(spki(e.publicKey)),kemPin:sha(spki(kem.publicKey)),dsaPin:sha(spki(dsa.publicKey)),controllerPublic:randomBytes(32).toString('base64url')};
 const {rootPin,pqRootPin,...device}=expected;
 const record={...device,backend:'windows-software-pq-storage-lab',status:'local-provision-only-not-enrolled',localReadback:'verified',signing:point(s.publicKey),encryption:point(e.publicKey),kemPublic:spki(kem.publicKey).toString('base64url'),dsaPublic:spki(dsa.publicKey).toString('base64url')};
 return {labOnly:true,handle,now,record,expected,ownerSigning:owner.privateKey,ownerPQ:root.privateKey,deviceSigning:s.privateKey,deviceECDH:e.privateKey,deviceKEM:kem.privateKey,deviceDSA:dsa.privateKey};
}
test('root-signed candidate is compatible with existing manifest/profile and authority quorum, but inactive by default',()=>{
 const f=fixture(),candidate=prepareNativeIdentityCandidate(f);
 assert.equal(candidate.registrationAuthorized,false);
 assert.equal(candidate.devicePossessionVerified,false);
 assert.equal(candidate.policyCandidate.active,false);
 const {bundle,policyCandidate:p}=candidate;
 const state={format:'quantic-relay-state',version:3,savedAt:new Date(f.now).toISOString(),manifests:[[p.address,bundle.manifest]],cryptoProfiles:[[p.address,bundle.profile]]};
 const request={address:p.address,deviceId:p.deviceId,nonce:randomBytes(32).toString('hex'),expires:f.now+10000};
 const authorities=Array.from({length:4},()=>generateKeyPairSync('ed25519'));
 const trusted=authorities.map(k=>({pin:sha(spki(k.publicKey)),publicKey:spki(k.publicKey).toString('base64url')}));
 assert.throws(()=>issueCheckpoint({state,policy:[p],request,privateKey:authorities[0].privateKey,now:f.now}));
 // Explicit synthetic activation tests compatibility only, not a real enrollment.
 const votes=authorities.map(k=>issueCheckpoint({state,policy:[{...p,active:true}],request,privateKey:k.privateKey,now:f.now}).attestation);
 assert.throws(()=>verifyCheckpointQuorum(votes.slice(0,2),trusted,request,f.now));
 const cp=verifyCheckpointQuorum(votes.slice(0,3),trusted,request,f.now);
 const c=bindNativeContact(bundle,cp,f.now);
 assert.equal(sha(Buffer.from(c.mlKemEncryptionSpki,'base64')),f.expected.kemPin);
 assert.equal(sha(Buffer.from(c.mlDsaSigningSpki,'base64')),f.expected.dsaPin);
 assert.equal(sha(Buffer.from(c.classicalSigningSpki,'base64')),f.expected.signingPin);
 assert.equal(sha(Buffer.from(c.classicalEncryptionSpki,'base64')),f.expected.encryptionPin);
});
test('wrong owner, device, quorum, key replacement and unverified or extra data refused',()=>{
 const f=fixture();
 for(const patch of [
  {labOnly:false},{handle:'bobby'},{ownerSigning:ec().privateKey},{ownerPQ:generateKeyPairSync('ml-dsa-65').privateKey},
  {expected:{...f.expected,quorumPin:'0'.repeat(64)}},
  {record:{...f.record,address:'bobby~'+'a'.repeat(32)+'@quantic'}},
  {record:{...f.record,deviceId:'d-'+'a'.repeat(32)}},
  {record:{...f.record,signing:point(ec().publicKey)}},
  {record:{...f.record,kemPublic:spki(generateKeyPairSync('ml-kem-768').publicKey).toString('base64url')}},
  {record:{...f.record,localReadback:'unverified'}},
  {record:{...f.record,privateKey:'should not be present'}}
 ])assert.throws(()=>prepareNativeIdentityCandidate({...f,...patch}));
});

const domain='quantic-native-enrollment-possession-lab/v1';
function deviceResponse(f,request,{wrongECDH=false,wrongKEM=false,wrongPQSignature=false}={}){
 const a=JSON.parse(request.challenge),ep=Buffer.from(a[12],'base64url');
 const pub=createPublicKey({key:{kty:'EC',crv:'P-256',x:ep.subarray(1,33).toString('base64url'),y:ep.subarray(33).toString('base64url')},format:'jwk'});
 const ec=diffieHellman({privateKey:wrongECDH?generateKeyPairSync('ec',{namedCurve:'prime256v1'}).privateKey:f.deviceECDH,publicKey:pub});
 const pq=decapsulate(wrongKEM?generateKeyPairSync('ml-kem-768').privateKey:f.deviceKEM,Buffer.from(a[13],'base64url'));
 const combined=Buffer.concat([ec,pq]),key=createHmac('sha256',domain).update(combined).digest();
 const mac=createHmac('sha256',key).update(request.challenge).digest();
 const tr=Buffer.concat([Buffer.from(domain+'\0'),Buffer.from(request.challenge),Buffer.from([0]),mac]);
 const response={status:'native-possession-lab-proof',challengeSha256:request.challengeSha256,classicalSignature:sign('sha256',tr,{key:f.deviceSigning,dsaEncoding:'ieee-p1363'}).toString('base64url'),pqSignature:sign(null,tr,wrongPQSignature?generateKeyPairSync('ml-dsa-65').privateKey:f.deviceDSA).toString('base64url')};
 for(const b of [ec,pq,combined,key,mac,tr])b.fill(0);
 return response;
}
test('four-key possession is verified once, without registration authority',()=>{
 const f=fixture(),candidate=prepareNativeIdentityCandidate(f);
 const r=issueNativePossessionChallenge(candidate,f.expected,{clock:()=>f.now});
 const response=deviceResponse(f,r);
 const result=r.verify(response);
 assert.equal(result.devicePossessionVerified,true);
 assert.equal(result.registrationAuthorized,false);
 assert.equal(result.candidateDigest,r.candidateDigest);
 assert.throws(()=>r.verify(response));
});
test('missing encryption possession, incorrect PQ signature, expired or reused challenge refused',()=>{
 const f=fixture(),candidate=prepareNativeIdentityCandidate(f);
 for(const patch of [{wrongECDH:true},{wrongKEM:true},{wrongPQSignature:true}]){
  const r=issueNativePossessionChallenge(candidate,f.expected,{clock:()=>f.now});
  assert.throws(()=>r.verify(deviceResponse(f,r,patch)));
  assert.throws(()=>r.verify(deviceResponse(f,r)));
 }
 let now=f.now;
 const r=issueNativePossessionChallenge(candidate,f.expected,{clock:()=>now});
 const response=deviceResponse(f,r);now=r.expires;
 assert.throws(()=>r.verify(response));
 const closed=issueNativePossessionChallenge(candidate,f.expected,{clock:()=>f.now});
 closed.close();assert.throws(()=>closed.verify(deviceResponse(f,closed)));
 const a=issueNativePossessionChallenge(candidate,f.expected,{clock:()=>f.now}),b=issueNativePossessionChallenge(candidate,f.expected,{clock:()=>f.now});
 assert.throws(()=>b.verify(deviceResponse(f,a)));a.close();
});

import {createNativeEnrollmentRegistryLab,verifyNativeEnrollmentReceipts} from '../lib/quantic/native-enrollment-registry-lab.mjs';
import {mkdtemp,mkdir,rm,readFile,writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
test('independent durable enrollment: three proofs, restart readback, address collision and tamper refusal',{skip:process.platform!=='linux'},async()=>{
 const f=fixture(),candidate=prepareNativeIdentityCandidate(f);
 const dir=await mkdtemp(join(tmpdir(),'native-enroll-'));
 try{
  const keys=Array.from({length:4},()=>generateKeyPairSync('ed25519'));
  const trust=keys.map(k=>({pin:sha(spki(k.publicKey)),publicKey:spki(k.publicKey).toString('base64url')}));
  const configs=await Promise.all(keys.map(async(k,i)=>{
   const directory=join(dir,'authority-'+i);await mkdir(directory,{mode:0o700});
   return {directory,authorityKey:k.privateKey,authorityPin:trust[i].pin,clock:()=>f.now,labOnly:true};
  }));
  const registries=await Promise.all(configs.map(createNativeEnrollmentRegistryLab));
  await assert.rejects(registries[0].begin(candidate,f.expected));
  const first=await registries[0].begin(candidate,f.expected,{operatorApproved:true});
  const competitor=await registries[0].begin(candidate,f.expected,{operatorApproved:true});
  const receipt=await first.commit(deviceResponse(f,first));
  await assert.rejects(competitor.commit(deviceResponse(f,competitor)));
  await assert.rejects(first.commit(deviceResponse(f,first)));
  await assert.rejects(registries[0].begin(candidate,f.expected,{operatorApproved:true}));
  const receipts=[receipt];
  for(const reg of registries.slice(1,3)){
   const c=await reg.begin(candidate,f.expected,{operatorApproved:true});
   receipts.push(await c.commit(deviceResponse(f,c)));
  }
  assert.throws(()=>verifyNativeEnrollmentReceipts(receipts.slice(0,2),trust,candidate,f.expected));
  assert.throws(()=>verifyNativeEnrollmentReceipts([receipt,receipt,receipts[1]],trust,candidate,f.expected));
  const result=verifyNativeEnrollmentReceipts(receipts,trust,candidate,f.expected);
  assert.equal(result.authorityCount,3);
  assert.equal(result.registrationAuthorized,false);
  assert.equal(result.mailPolicyActive,false);
  const reopened=await createNativeEnrollmentRegistryLab(configs[0]);
  assert.deepEqual(await reopened.readback(candidate,f.expected),receipt);
  const fourth=await registries[3].begin(candidate,f.expected,{operatorApproved:true});
  await assert.rejects(fourth.commit(deviceResponse(f,fourth,{wrongKEM:true})));
  await assert.rejects(registries[3].readback(candidate,f.expected));
  const path=join(configs[0].directory,'identity-'+sha(f.expected.address)+'.json');
  const stored=JSON.parse(await readFile(path,'utf8'));
  stored.receipt.deviceId='d-'+'0'.repeat(32);
  await writeFile(path,JSON.stringify(stored));
  await assert.rejects(reopened.readback(candidate,f.expected));
  await assert.rejects(reopened.begin(candidate,f.expected,{operatorApproved:true}));
 }finally{await rm(dir,{recursive:true,force:true});}
});
