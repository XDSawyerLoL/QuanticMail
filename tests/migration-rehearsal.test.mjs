import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync,sign} from 'node:crypto';
import {canonicalManifestText} from '../lib/quantic/manifest-core.mjs';
import {canonicalCryptoProfileText} from '../lib/quantic/crypto-profile-core.mjs';
import {canonicalPreKeyText} from '../lib/quantic/prekey-core.mjs';
import {prepareMigrationArchive,sealMigrationArchive} from '../lib/quantic/migration-archive.ts';
import {rehearseNativeIdentityMigration} from '../lib/quantic/migration-rehearsal.mjs';
const ec=()=>generateKeyPairSync('ec',{namedCurve:'prime256v1'});
const dsa=()=>generateKeyPairSync('ml-dsa-65'),kem=()=>generateKeyPairSync('ml-kem-768');
const jwk=k=>k.publicKey.export({format:'jwk'});
const spki=k=>k.publicKey.export({type:'spki',format:'der'});
const privateJwk=k=>k.privateKey.export({format:'jwk'});
const pkcs8=k=>k.privateKey.export({type:'pkcs8',format:'der'}).toString('base64url');
const sha=x=>createHash('sha256').update(x).digest('hex');
const fingerprint=k=>sha('P-256:'+jwk(k).x+':'+jwk(k).y).slice(0,32);
const deviceId=k=>'d-'+fingerprint(k);
const signed=(root,payload)=>({
 format:'quantic-identity-manifest',version:1,payload,
 signature:sign('sha256',Buffer.from(canonicalManifestText(payload)),{
  key:root.privateKey,dsaEncoding:'ieee-p1363'
 }).toString('base64')
});
function fixture(){
 const root=ec(),enc=ec(),oldSigner=ec(),nativeEnc=ec(),nativeSigner=ec(),preKey=ec();
 const oldKem=kem(),oldDsa=dsa(),pqRoot=dsa(),nativeKem=kem(),nativeDsa=dsa();
 const date=new Date(Date.now()-5000).toISOString();
 const address='alice~'+fingerprint(root)+'@quantic';
 const oldId=deviceId(enc),newId=deviceId(nativeEnc);
 const legacyDevice={deviceId:oldId,label:'Original browser',publicKey:jwk(enc),
  deviceSigningPublicKey:jwk(oldSigner),kind:'root',issuedAt:date};
 const newDevice={deviceId:newId,label:'Native laboratory',publicKey:jwk(nativeEnc),
  deviceSigningPublicKey:jwk(nativeSigner),kind:'linked',issuedAt:date};
 const rootPayload={version:1,sequence:1,canonicalAddress:address,handle:'alice',
  fingerprint:fingerprint(root),identityPublicKey:jwk(enc),identitySigningPublicKey:jwk(root),
  devices:[legacyDevice],revocations:[],issuedAt:date};
 const currentPayload={...rootPayload,sequence:2,devices:[legacyDevice,newDevice]};
 const historical=signed(root,rootPayload),current=signed(root,currentPayload);
 const pqSpki=k=>spki(k).toString('base64url');
 const profilePayload={version:2,sequence:1,canonicalAddress:address,
  identitySigningPublicKey:jwk(root),identityManifestSequence:2,policy:'hybrid-required',
  identityMlDsaAlgorithm:'ML-DSA-65',identityMlDsaPublicKeySpki:pqSpki(pqRoot),
  devices:[
   {deviceId:oldId,mlKemAlgorithm:'ML-KEM-768',mlKemPublicKeySpki:pqSpki(oldKem),
    mlDsaAlgorithm:'ML-DSA-65',mlDsaPublicKeySpki:pqSpki(oldDsa)},
   {deviceId:newId,mlKemAlgorithm:'ML-KEM-768',mlKemPublicKeySpki:pqSpki(nativeKem),
    mlDsaAlgorithm:'ML-DSA-65',mlDsaPublicKeySpki:pqSpki(nativeDsa)}
  ],issuedAt:date};
 const raw=canonicalCryptoProfileText(profilePayload);
 const profile={format:'quantic-crypto-profile',version:2,payload:profilePayload,
  signatures:{p256:sign('sha256',Buffer.from(raw),{key:root.privateKey,
   dsaEncoding:'ieee-p1363'}).toString('base64'),
   mlDsa65Self:sign(null,Buffer.from(raw),pqRoot.privateKey).toString('base64url')}};
 const exp=Date.now()+20000;
 const checkpoint={address,deviceId:oldId,rootPin:sha(spki(root)),
  pqRootPin:sha(spki(pqRoot)),manifestSequence:2,profileSequence:1,
  manifestDigest:sha(canonicalManifestText(currentPayload)),profileDigest:sha(raw),expires:exp};
 const archive=prepareMigrationArchive({
  identity:{role:'root',handle:'alice',address,canonicalAddress:address,fingerprint:fingerprint(root),
   deviceId:oldId,publicKey:jwk(enc),privateKey:privateJwk(enc),
   signingPublicKey:jwk(root),signingPrivateKey:privateJwk(root),
   deviceSigningPublicKey:jwk(oldSigner),deviceSigningPrivateKey:privateJwk(oldSigner),
   manifest:historical,authToken:'NEVER_LEAVE_SOURCE',
   pqc:{version:1,mlKemPublicKeySpki:pqSpki(oldKem),
    mlKemPrivateKeyPkcs8:pkcs8(oldKem),mlDsaPublicKeySpki:pqSpki(oldDsa),
    mlDsaPrivateKeyPkcs8:pkcs8(oldDsa),createdAt:date}},
  pending:null,prekeys:[],messages:[{id:'historical-1',direction:'in',from:'bob@quantic',
   to:address,subject:'archive encrypted',body:'historical plaintext',createdAt:date}],
  contacts:[{handle:'bob',address:'bob@quantic',firstSeenAt:date,lastSeenAt:date}],
  outbox:[{id:'pending-1',from:address,to:'bob@quantic',ciphertext:'c2VjcmV0',
   iv:'YWJjZGVmZ2hpamts',ephemeralPublicKey:jwk(ec()),createdAt:date}]
 });
 const peerById=new Map([
  [oldId,{bundle:{manifest:current,profile},checkpoint:{...checkpoint,deviceId:oldId}}],
  [newId,{bundle:{manifest:current,profile},checkpoint:{...checkpoint,deviceId:newId}}]
 ]);
 const expected={expectedAddress:address,trustedRootPin:sha(spki(root)),newDeviceId:newId,
  pqRootPin:sha(spki(pqRoot)),
  newDevicePins:[spki(nativeSigner),spki(nativeEnc),spki(nativeKem),spki(nativeDsa)].map(sha),
  peerSource:async(a,d)=>{assert.equal(a,address);const data=peerById.get(d);
    if(!data)throw Error('no native authority attestation');return structuredClone(data);}
 };
 return {archive,expected,peerById,oldId,newId,root,pqRoot,currentPayload};
}
const password='synthetic rehearsal password never production';
test('trusted offline archive and current native hybrid keys are cross-checked; no live cutover',async()=>{
 const f=fixture(),archiveText=await sealMigrationArchive(f.archive,password);
 const report=await rehearseNativeIdentityMigration({archiveText,password,...f.expected});
 assert.equal(report.historicalKeysVerified,true);
 assert.equal(report.oldDeviceStillActive,true);
 assert.equal(report.nativePublicKeysPinned,true);
 assert.equal(report.postQuantumHistoricalKeysMatched,true);
 assert.equal(report.postQuantumAccountRootPrivateKeyVerified,false);
 assert.equal(report.pqRootLineageVerified,false);
 assert.ok(report.blockers.includes('previous-pq-root-lineage-not-independently-proven'));
 assert.ok(report.blockers.includes('pq-account-root-private-key-custody-not-established'));
 assert.equal(report.currentManifestSequence,2);
 assert.equal(report.historicalManifestSequence,1);
 assert.deepEqual(report.archiveCounts,{messages:1,contacts:1,prekeys:0,outbox:1});
 for(const flag of ['nativeKeysImported','liveRegistrationAuthorized','liveRestoreAuthorized',
  'legacyDeletionAuthorized','physicalDeviceTested'])assert.equal(report[flag],false);
 const output=JSON.stringify(report);
 for(const secret of ['NEVER_LEAVE_SOURCE',f.archive.identity.privateKey.d,
  f.archive.identity.pqc.mlKemPrivateKeyPkcs8,'historical plaintext'])assert.ok(!output.includes(secret));
});
test('rehearsal refuses unauthorized archive roots, substituted PQ roots, stale active devices and registry races',async()=>{
 const f=fixture(),text=await sealMigrationArchive(f.archive,password);
 const rehearse=(changes={})=>rehearseNativeIdentityMigration({
  archiveText:text,password,...f.expected,...changes
 });
 await assert.rejects(rehearse({trustedRootPin:'f'.repeat(64)}));
 await assert.rejects(rehearse({pqRootPin:'f'.repeat(64)}));
 await assert.rejects(rehearse({newDevicePins:Array(4).fill('b'.repeat(64))}));
 await assert.rejects(rehearse({newDeviceId:f.oldId}));
 const f2=fixture(),m=structuredClone(f2.archive);m.pending={deviceId:'pending-device'};
 await assert.rejects(rehearse({archiveText:await sealMigrationArchive(m,password)}));
 const missing=async(a,d)=>d===f.newId?Promise.reject(Error('missing linked device')):f.expected.peerSource(a,d);
 await assert.rejects(rehearse({peerSource:missing}));
 let calls=0;
 const rollback=async(a,d)=>{
  const current=await f.expected.peerSource(a,d);calls++;
  if(calls>2)current.checkpoint.manifestSequence=1;
  return current;
 };
 await assert.rejects(rehearse({peerSource:rollback}));
 let count=0;
 const swappedIdentityOnReread=async(a,d)=>{
  count++;
  // The second read of the new device returns a different, still
  // cryptographically valid device on the same authority.
  if(count===4)return f.expected.peerSource(a,f.oldId);
  return f.expected.peerSource(a,d);
 };
 await assert.rejects(rehearse({peerSource:swappedIdentityOnReread}));
 const oldProfileSwap=async(a,d)=>{
  const current=await f.expected.peerSource(a,d);
  current.bundle.profile.payload.devices.find(x=>x.deviceId===f.oldId).mlKemPublicKeySpki
    =spki(kem()).toString('base64url');
  return current;
 };
 await assert.rejects(rehearse({peerSource:oldProfileSwap}));
});

test('migration rehearsal refuses forged PQ lineage evidence rather than reporting a successful preflight',async()=>{
 const f=fixture();
 const archiveText=await sealMigrationArchive(f.archive,password);
 await assert.rejects(rehearseNativeIdentityMigration({
   archiveText,password,...f.expected,
   rootTransitionEvidence:{
     previousIdentityManifest:f.archive.identity.manifest,
     previousCryptoProfile:f.peerById.get(f.oldId).bundle.profile,
     previousProfileDigest:'f'.repeat(64),
     previousPqRootPin:f.expected.pqRootPin,
   }
 }));
});
