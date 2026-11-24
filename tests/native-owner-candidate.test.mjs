import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync,randomBytes} from 'node:crypto';
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
 return {labOnly:true,handle,now,record,expected,ownerSigning:owner.privateKey,ownerPQ:root.privateKey};
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
