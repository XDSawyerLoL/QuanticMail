import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,createHash,sign,createPublicKey,diffieHellman,decapsulate,hkdfSync,createDecipheriv} from 'node:crypto';
import {canonicalManifestText} from '../lib/quantic/manifest-core.mjs';
import {canonicalCryptoProfileText} from '../lib/quantic/crypto-profile-core.mjs';
import {prepareNativePossessionChallenge} from '../desktop/native-enrollment-possession.mjs';
import {enrollmentRosterPin,verifyNativeEnrollmentQuorum,prepareQuorumEnrollmentPolicy,enrollmentVoteTranscript} from '../desktop/native-enrollment-quorum.mjs';
import {issueCheckpoint,verifyCheckpointQuorum} from '../lib/quantic/native-checkpoint-authority.mjs';
const hash=x=>createHash('sha256').update(x).digest('hex');
const ec=()=>generateKeyPairSync('ec',{namedCurve:'prime256v1'});
const jwk=k=>k.publicKey.export({format:'jwk'});
const der=k=>k.publicKey.export({format:'der',type:'spki'});
const fp=j=>hash('P-256:'+j.x+':'+j.y).slice(0,32);
const sig=(k,b)=>sign('sha256',b,{key:k.privateKey,dsaEncoding:'ieee-p1363'}).toString('base64');
const buf=x=>Buffer.from(JSON.stringify(x));
function fixture(){
 const now=Date.now(),stamp=new Date(now).toISOString(),owner=ec(),enc=ec(),signer=ec(),
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
 const controllerPublic=Buffer.alloc(32,7).toString('base64url'),format='quantic-native-enrollment-request-lab/v1';
 const tr=buf([format,address,deviceId,claim.rootPin,claim.pqRootPin,claim.manifestDigest,claim.profileDigest,quorumPin,controllerPublic]);
 const request={format,quorumPin,controllerPublic,claim,ownerP256Signature:sig(owner,tr),ownerMlDsaSignature:sign(null,tr,root.privateKey).toString('base64url')};
 const authority=Array.from({length:4},()=>generateKeyPairSync('ed25519'));
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
 return {now,request,opts,votes,authority,prepare,respond,state};
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
