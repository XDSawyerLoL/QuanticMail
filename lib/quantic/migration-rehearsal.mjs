// Trusted local Node 24 experimental recovery rehearsal, NOT a live
// migration. Enforces joint historical key possession + authoritative native
// PQ continuity without transmitting archive private keys or bearer tokens.
// No registry writes, native secret import, user enrollment or deletion.
import {createHash} from 'node:crypto';
import {openMigrationArchive} from './migration-archive.ts';
import {verifyMigrationArchiveOffline} from './migration-proof-node.mjs';
import {checkMigrationContinuity} from './migration-continuity.mjs';
import {verifyNativePqRootTransition} from './native-pq-root-transition.mjs';
import {assertVerifiedManifest} from './manifest-node.mjs';
import {bindNativeContact} from './native-identity-bridge.mjs';
const check=v=>{if(!v)throw Error('Historical to native migration rehearsal refused');};
const hex=/^[a-f0-9]{64}$/;
const sha=b=>createHash('sha256').update(b).digest('hex');
function strictSpki(text,expectedSize){
 check(typeof text==='string'&&/^[A-Za-z0-9_-]+$/.test(text));
 const bytes=Buffer.from(text,'base64url');
 check(bytes.length===expectedSize&&bytes.toString('base64url')===text);
 return bytes;
}
function records(rows,key){
 check(Array.isArray(rows)&&rows.length<=10000);
 const seen=new Set();
 for(const row of rows){
  const k=row?.[key];
  check(typeof k==='string'&&k.length>0&&k.length<=512&&!seen.has(k));
  seen.add(k);
 }
 return seen.size;
}
const highWater=cp=>[cp?.address,cp?.manifestSequence,cp?.profileSequence,
 cp?.manifestDigest,cp?.profileDigest,cp?.rootPin,cp?.pqRootPin];
export async function rehearseNativeIdentityMigration({
 archiveText,password,expectedAddress,trustedRootPin,newDeviceId,
 pqRootPin,newDevicePins,peerSource,rootTransitionEvidence=null,now=Date.now()
}){
 check(Number.isSafeInteger(now)&&now>=0&&typeof peerSource==='function');
 check(hex.test(trustedRootPin)&&hex.test(pqRootPin));
 // Read the password-protected source history only inside the trusted
 // process. The returned report is intentionally devoid of key material.
 const proof=await verifyMigrationArchiveOffline(archiveText,password,{expectedAddress,trustedRootPin});
 check(proof.historicalRootPinVerified===true&&proof.rootPrivateKeyVerified===true
  &&proof.deviceKeyPossessionVerified===true
  &&proof.postQuantumKeyPairsVerified===true
  &&proof.pendingRequiresResolution===false);
 const history=await openMigrationArchive(archiveText,password,expectedAddress);
 check(history.identity?.role==='root'&&history.pending===null
  &&history.identity?.manifest?.payload?.canonicalAddress===expectedAddress);
 const oldDeviceId=history.identity.deviceId;
 check(typeof oldDeviceId==='string'&&/^d-[a-f0-9]{32}$/.test(oldDeviceId));
 for(const [rows,key] of [
  [history.messages,'id'],[history.contacts,'handle'],
  [history.prekeys,'preKeyId'],[history.outbox,'id']
 ])records(rows,key);
 // The archive proof reports the number of cryptographically verified prekeys.
 // Require an exact inventory match before reporting a successful rehearsal.
 check(Number.isSafeInteger(proof.prekeyPairsVerified)
  &&proof.prekeyPairsVerified===history.prekeys.length);
 const pq=history.identity.pqc;
 check(pq?.version===1&&pq.mlDsaPublicKeySpki&&pq.mlKemPublicKeySpki);
 // Browser device PQ key continuity is NOT automatically PQ account-root
 // continuity. Require a separately pinned, independently attested root;
 // any unreviewed rotation fails closed.
 const historicalDsa=sha(strictSpki(pq.mlDsaPublicKeySpki,1974));
 const historicalKem=sha(strictSpki(pq.mlKemPublicKeySpki,1206));
 // The historical device ML-DSA key need not be the account's PQ root;
 // never conflate device possession with PQ account-root custody.
 const saved=assertVerifiedManifest(history.identity.manifest);
 check(saved.payload.canonicalAddress===expectedAddress);
 const observed=new Map();
 const trusted=async(address,device)=>{
  check(address===expectedAddress&&(device===oldDeviceId||device===newDeviceId));
  const r=await peerSource(address,device);
  check(r?.checkpoint&&r?.bundle);
  const contact=bindNativeContact(r.bundle,r.checkpoint);
  check(contact.address===address&&contact.deviceId===device);
  observed.set(device,{checkpoint:structuredClone(r.checkpoint),bundle:structuredClone(r.bundle)});
  return r;
 };
 const continuity=await checkMigrationContinuity({
  historicalManifest:saved,address:expectedAddress,
  oldDeviceId,newDeviceId,rootPin:trustedRootPin,pqRootPin,newDevicePins,
  peerSource:trusted
 });
 check(continuity.sameIdentity&&continuity.previousDeviceActive
  &&continuity.newDeviceAttested&&continuity.manifestSequence>saved.payload.sequence);
 const old=observed.get(oldDeviceId),next=observed.get(newDeviceId);
 check(old&&next);
 const profile=old.bundle.profile;
 const oldPQ=profile?.payload?.devices?.find(d=>d.deviceId===oldDeviceId);
 const currentRoot=profile?.payload?.identityMlDsaPublicKeySpki;
 check(oldPQ&&currentRoot
  &&sha(strictSpki(currentRoot,1974))===pqRootPin
  &&sha(strictSpki(oldPQ.mlDsaPublicKeySpki,1974))===historicalDsa
  &&sha(strictSpki(oldPQ.mlKemPublicKeySpki,1206))===historicalKem);
 // Optional independent PQ-root lineage preflight. Absence is an explicit
 // blocker, never an implicit consent or permission to migrate real keys.
 // The prior root pin and prior Crypto Profile digest MUST be obtained from
 // an independently trusted record, not merely the uploaded archive.
 const rootTransition=rootTransitionEvidence===null?null:verifyNativePqRootTransition({
   previousIdentityManifest:rootTransitionEvidence.previousIdentityManifest,
   previousCryptoProfile:rootTransitionEvidence.previousCryptoProfile,
   previousProfileDigest:rootTransitionEvidence.previousProfileDigest,
   previousPqRootPin:rootTransitionEvidence.previousPqRootPin,
   historicalRootPin:trustedRootPin,
   expectedCurrentPqRootPin:pqRootPin,
   currentIdentityManifest:old.bundle.manifest,
   currentCryptoProfile:old.bundle.profile,
 });
 const historicalPqRootPossessed=historicalDsa===pqRootPin;
 // A second independently verified read detects changes while the
 // rehearsal was running. A real cutover must still use CAS and commits.
 for(const id of [oldDeviceId,newDeviceId]){
  const previous=observed.get(id).checkpoint;
  const fresh=await peerSource(expectedAddress,id);
  const contact=bindNativeContact(fresh.bundle,fresh.checkpoint);
  check(contact.address===expectedAddress&&contact.deviceId===id);
  check(JSON.stringify(highWater(fresh.checkpoint))===JSON.stringify(highWater(previous)));
  check(fresh.checkpoint.expires>Date.now());
 }
 return Object.freeze({
  historicalKeysVerified:true,historicalPrekeysVerified:true,
  historicalManifestSequence:saved.payload.sequence,
  currentManifestSequence:continuity.manifestSequence,
  currentProfileSequence:continuity.profileSequence,
  nativePublicKeysPinned:true,oldDeviceStillActive:true,
  postQuantumHistoricalKeysMatched:true,
  postQuantumAccountRootPrivateKeyVerified:historicalPqRootPossessed,
  pqRootLineageVerified:rootTransition?.authenticatedPqRootContinuity===true,
  authorityRechecked:true,
  archiveCounts:Object.freeze({
   messages:history.messages.length,contacts:history.contacts.length,
   prekeys:history.prekeys.length,outbox:history.outbox.length
  }),
  // Never let a dry-run status become a registration or deletion grant.
  nativeKeysImported:false,liveRegistrationAuthorized:false,
  liveRestoreAuthorized:false,legacyDeletionAuthorized:false,
  physicalDeviceTested:false,labOnly:true,
  blockers:Object.freeze([
   'actual-native-key-custody-not-audited',
   'historical-mail-bitwise-recovery-pending',
   'new-native-device-live-signing-and-decryption-pending',
   'fresh-atomic-registry-cutover-pending',
   'old-browser-root-still-extractable',
   ...(rootTransition?[]:['previous-pq-root-lineage-not-independently-proven']),
   ...(historicalPqRootPossessed?[]:['pq-account-root-private-key-custody-not-established'])
  ])
 });
}
