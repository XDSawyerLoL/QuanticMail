import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync,sign} from 'node:crypto';
import {canonicalManifestText} from '../lib/quantic/manifest-core.mjs';
import {canonicalCryptoProfileText} from '../lib/quantic/crypto-profile-core.mjs';
import {verifyNativePqRootTransition} from '../lib/quantic/native-pq-root-transition.mjs';

const hash=data=>createHash('sha256').update(data).digest('hex');
const ec=()=>generateKeyPairSync('ec',{namedCurve:'prime256v1'});
const pq=()=>generateKeyPairSync('ml-dsa-65');
const kem=()=>generateKeyPairSync('ml-kem-768');
const jwk=pair=>pair.publicKey.export({format:'jwk'});
const der=pair=>pair.publicKey.export({format:'der',type:'spki'});
const b64=pair=>der(pair).toString('base64url');
const sig=(pair,text)=>sign('sha256',Buffer.from(text),{
  key:pair.privateKey,dsaEncoding:'ieee-p1363'}).toString('base64');
const dsaSig=(pair,text)=>sign(null,Buffer.from(text),pair.privateKey).toString('base64url');

function fixture() {
  const owner=ec(),deviceKey=ec(),signer=ec(),nativeKey=ec(),nativeSigner=ec();
  const oldPq=pq(),newPq=pq(),oldKem=kem(),oldDsa=pq(),newKem=kem(),newDsa=pq();
  const issuedAt='2026-11-23T09:00:00.000Z';
  const fp=hash('P-256:'+jwk(owner).x+':'+jwk(owner).y).slice(0,32);
  const address='identity~'+fp+'@quantic';
  const did=key=>'d-'+hash('P-256:'+jwk(key).x+':'+jwk(key).y).slice(0,32);
  const originalId=did(deviceKey),nativeId=did(nativeKey);
  const rootDevice={deviceId:originalId,kind:'root',label:'Historical browser',
    publicKey:jwk(deviceKey),deviceSigningPublicKey:jwk(signer),issuedAt};
  const linkedDevice={deviceId:nativeId,kind:'linked',label:'Native test device',
    publicKey:jwk(nativeKey),deviceSigningPublicKey:jwk(nativeSigner),issuedAt};
  const manifestPayload=(sequence,devices)=>({
    version:1,sequence,canonicalAddress:address,handle:'identity',fingerprint:fp,
    identityPublicKey:jwk(deviceKey),identitySigningPublicKey:jwk(owner),
    devices,revocations:[],issuedAt,
  });
  const oldManifestPayload=manifestPayload(1,[rootDevice]);
  const newManifestPayload=manifestPayload(2,[rootDevice,linkedDevice]);
  const manifest=payload=>({format:'quantic-identity-manifest',version:1,payload,
    signature:sig(owner,canonicalManifestText(payload))});
  const pqDevice=(id,k,d)=>({deviceId:id,mlKemAlgorithm:'ML-KEM-768',
    mlKemPublicKeySpki:b64(k),mlDsaAlgorithm:'ML-DSA-65',
    mlDsaPublicKeySpki:b64(d)});
  const profilePayload=(sequence,manifestSequence,root,devices)=>({
    version:2,sequence,canonicalAddress:address,identitySigningPublicKey:jwk(owner),
    identityManifestSequence:manifestSequence,policy:'hybrid-required',
    identityMlDsaAlgorithm:'ML-DSA-65',identityMlDsaPublicKeySpki:b64(root),
    devices,issuedAt,
  });
  const oldProfilePayload=profilePayload(1,1,oldPq,[pqDevice(originalId,oldKem,oldDsa)]);
  const newProfilePayload=profilePayload(2,2,newPq,[
    pqDevice(originalId,oldKem,oldDsa),pqDevice(nativeId,newKem,newDsa)]);
  const profile=(payload,root,previous=null)=>{
    const txt=canonicalCryptoProfileText(payload);
    return {format:'quantic-crypto-profile',version:2,payload,signatures:{
      p256:sig(owner,txt),mlDsa65Self:dsaSig(root,txt),
      ...(previous?{mlDsa65Continuity:dsaSig(previous,txt)}:{})
    }};
  };
  const args={
    previousIdentityManifest:manifest(oldManifestPayload),
    previousCryptoProfile:profile(oldProfilePayload,oldPq),
    currentIdentityManifest:manifest(newManifestPayload),
    currentCryptoProfile:profile(newProfilePayload,newPq,oldPq),
    previousProfileDigest:hash(canonicalCryptoProfileText(oldProfilePayload)),
    historicalRootPin:hash(der(owner)),
    previousPqRootPin:hash(der(oldPq)),
    expectedCurrentPqRootPin:hash(der(newPq)),
  };
  return {args,owner,oldPq,newPq,profile};
}
test('native PQ transition accepts P-256 and ML-DSA history plus externally pinned 1→2 succession',()=>{
  const f=fixture();
  const result=verifyNativePqRootTransition(f.args);
  assert.equal(result.previousProfilePinned,true);
  assert.equal(result.authenticatedPqRootContinuity,true);
  assert.equal(result.previousProfileSequence,1);
  assert.equal(result.nextProfileSequence,2);
  for(const k of ['liveRegistrationAuthorized','liveRestoreAuthorized','legacyDeletionAuthorized',
    'physicalDeviceTested','independentAuditorApproved'])assert.equal(result[k],false);
  const publicReport=JSON.stringify(result);
  assert.ok(!publicReport.includes('private'));
});
test('the stolen historical P-256 signer cannot substitute a new PQ root without the old PQ signature',()=>{
  const f=fixture();
  const replacement=pq();
  const next=structuredClone(f.args.currentCryptoProfile);
  next.payload.identityMlDsaPublicKeySpki=b64(replacement);
  // Attacker signs with compromised historical P-256 key and replacement PQ key.
  const txt=canonicalCryptoProfileText(next.payload);
  next.signatures.p256=sig(f.owner,txt);
  next.signatures.mlDsa65Self=dsaSig(replacement,txt);
  delete next.signatures.mlDsa65Continuity;
  assert.throws(()=>verifyNativePqRootTransition({
    ...f.args,currentCryptoProfile:next,expectedCurrentPqRootPin:hash(der(replacement))
  }),/continuit/i);
});
test('valid continuity cannot bypass externally pinned destination PQ identity',()=>{
  const f=fixture();
  assert.throws(()=>verifyNativePqRootTransition({
    ...f.args,expectedCurrentPqRootPin:'f'.repeat(64)
  }),/refused/);
  assert.throws(()=>verifyNativePqRootTransition({
    ...f.args,previousPqRootPin:'f'.repeat(64)
  }),/refused/);
  assert.throws(()=>verifyNativePqRootTransition({
    ...f.args,previousProfileDigest:'f'.repeat(64)
  }),/refused/);
  assert.throws(()=>verifyNativePqRootTransition({
    ...f.args,historicalRootPin:'f'.repeat(64)
  }),/refused/);
});
test('rollback, fork, missing PQ continuity and downgrade are refused',()=>{
  const f=fixture();
  const missing=structuredClone(f.args.currentCryptoProfile);
  delete missing.signatures.mlDsa65Continuity;
  assert.throws(()=>verifyNativePqRootTransition({
    ...f.args,currentCryptoProfile:missing
  }),/continuit/i);
  const same=structuredClone(f.args.currentCryptoProfile);
  same.payload.sequence=1;
  const text=canonicalCryptoProfileText(same.payload);
  same.signatures.p256=sig(f.owner,text);
  same.signatures.mlDsa65Self=dsaSig(f.newPq,text);
  same.signatures.mlDsa65Continuity=dsaSig(f.oldPq,text);
  assert.throws(()=>verifyNativePqRootTransition({
    ...f.args,currentCryptoProfile:same
  }),/séquence|refused/i);
  const classical=structuredClone(f.args.currentCryptoProfile);
  classical.payload.policy='transition';
  const canonical=canonicalCryptoProfileText(classical.payload);
  classical.signatures.p256=sig(f.owner,canonical);
  classical.signatures.mlDsa65Self=dsaSig(f.newPq,canonical);
  classical.signatures.mlDsa65Continuity=dsaSig(f.oldPq,canonical);
  assert.throws(()=>verifyNativePqRootTransition({
    ...f.args,currentCryptoProfile:classical
  }),/Downgrade|refused/);
  const fork=structuredClone(f.args.currentIdentityManifest);
  fork.payload.sequence=1;
  fork.signature=sig(f.owner,canonicalManifestText(fork.payload));
  assert.throws(()=>verifyNativePqRootTransition({
    ...f.args,currentIdentityManifest:fork
  }),/Conflit|refused|fork/);
});
test('altered historic profile, invalid PQ self-signature and missing independent evidence fail closed',()=>{
 const f=fixture();
 const previous=structuredClone(f.args.previousCryptoProfile);
 previous.payload.identityMlDsaPublicKeySpki=b64(pq());
 assert.throws(()=>verifyNativePqRootTransition({
   ...f.args,previousCryptoProfile:previous
 }),/ML-DSA|P-256|refused/);
 const corrupt=structuredClone(f.args.currentCryptoProfile);
 corrupt.signatures.mlDsa65Self='A'.repeat(100);
 assert.throws(()=>verifyNativePqRootTransition({
   ...f.args,currentCryptoProfile:corrupt
 }),/ML-DSA|refused/);
 assert.throws(()=>verifyNativePqRootTransition({
   ...f.args,previousProfileDigest:undefined
 }),/refused/);
});
