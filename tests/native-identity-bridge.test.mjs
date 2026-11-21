import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync,sign,randomBytes} from 'node:crypto';
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
 return {bundle:{manifest,profile},checkpoint,ds,dsa,owner};
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
