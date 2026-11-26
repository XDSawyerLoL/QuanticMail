// Laboratory enrollment decisions. Separate roster pin (four checkpoint
// operator signing keys) from the vault's transport/journal quorum pin.
// No automatic state publication, account registration or credential issuance.
import {createHash,createPublicKey,verify} from 'node:crypto';
import {verifyNativeEnrollmentRequest} from './native-enrollment-claim.mjs';
import {bindNativeContact} from '../lib/quantic/native-identity-bridge.mjs';
const check=v=>{if(!v)throw Error('Native enrollment quorum refused');};
const hex=/^[0-9a-f]{64}$/;
const sha=v=>createHash('sha256').update(v).digest('hex');
const canonical=v=>Buffer.from(JSON.stringify(v));
const domain='quantic-native-enrollment-vote-lab/v1';
export const ENROLLMENT_VOTE_TTL=900000;
function exact(o,keys){check(o&&typeof o==='object'&&!Array.isArray(o)&&Object.keys(o).length===keys.length&&keys.every(k=>Object.hasOwn(o,k)));}
function publicKey(s){
 check(typeof s==='string'&&/^[A-Za-z0-9_-]{59}$/.test(s));
 const raw=Buffer.from(s,'base64url');check(raw.length===44&&raw.toString('base64url')===s);
 const key=createPublicKey({key:raw,type:'spki',format:'der'});check(key.asymmetricKeyType==='ed25519');
 return {key,pin:sha(raw)};
}
export function enrollmentRosterPin(trusted){
 check(Array.isArray(trusted)&&trusted.length===4);
 const pins=trusted.map(t=>{const p=publicKey(t.publicKey);check(p.pin===t.pin);return p.pin;}).sort();
 check(new Set(pins).size===4);
 return sha(canonical(['quantic-enrollment-roster-lab/v1','3-of-4',...pins]));
}
export function enrollmentRequestDigest(request,claim){
 return sha(canonical(['quantic-enrollment-claim-binding-lab/v1',claim.address,claim.deviceId,claim.rootPin,claim.pqRootPin,
 claim.signingPin,claim.encryptionPin,claim.kemPin,claim.dsaPin,claim.manifestDigest,claim.profileDigest,claim.quorumPin,request.controllerPublic]));
}
export function enrollmentVoteTranscript(v){
 exact(v,['format','authorityPin','rosterPin','requestDigest','proofDigest','issuedAt','expires','decision']);
 check(v.format===domain&&v.decision==='approve'&&[v.authorityPin,v.rosterPin,v.requestDigest,v.proofDigest].every(x=>typeof x==='string'&&hex.test(x)));
 check(Number.isSafeInteger(v.issuedAt)&&v.issuedAt>0&&v.expires===v.issuedAt+ENROLLMENT_VOTE_TTL);
 return canonical([domain,v.authorityPin,v.rosterPin,v.requestDigest,v.proofDigest,v.issuedAt,v.expires,v.decision]);
}
export function verifyNativeEnrollmentQuorum(request,votes,{trusted,rosterPin,quorumPin,now=Date.now()}={}){
 check(typeof rosterPin==='string'&&hex.test(rosterPin)&&enrollmentRosterPin(trusted)===rosterPin);
 const claim=verifyNativeEnrollmentRequest(request,{quorumPin,now});
 const digest=enrollmentRequestDigest(request,claim);
 check(Array.isArray(votes)&&votes.length>=3&&votes.length<=4);
 const keys=new Map(trusted.map(t=>[t.pin,publicKey(t.publicKey).key]));
 const seen=new Set(),proofs=new Set(),accepted=[];
 for(const vote of votes){
  try{
   exact(vote,['payload','signature']);const v=vote.payload,raw=enrollmentVoteTranscript(v);
   check(keys.has(v.authorityPin)&&!seen.has(v.authorityPin)&&!proofs.has(v.proofDigest)&&v.rosterPin===rosterPin&&v.requestDigest===digest&&v.issuedAt<=now&&v.expires>now);
   check(typeof vote.signature==='string'&&/^[A-Za-z0-9_-]{86}$/.test(vote.signature));
   const sig=Buffer.from(vote.signature,'base64url');check(sig.length===64&&sig.toString('base64url')===vote.signature&&verify(null,raw,keys.get(v.authorityPin),sig));
   seen.add(v.authorityPin);proofs.add(v.proofDigest);accepted.push(v);
  }catch{/* Invalid or duplicate votes have zero weight. */}
 }
 check(accepted.length>=3);
 const policyCandidate={address:claim.address,deviceId:claim.deviceId,rootPin:claim.rootPin,pqRootPin:claim.pqRootPin,
 manifestSequence:1,profileSequence:1,manifestDigest:claim.manifestDigest,profileDigest:claim.profileDigest,active:false};
 return Object.freeze({status:'enrollment-quorum-approved-pending-publication',labOnly:true,requestDigest:digest,rosterPin,
 approvals:accepted.length,expires:Math.min(...accepted.map(v=>v.expires)),policyCandidate:Object.freeze(policyCandidate),remotelyEnrolled:false,mailAuthorized:false});
}
// Prepare ONE independent operator's policy update. The caller must provide
// the current authenticated relay snapshot and its existing policy. Never
// synthesize savedAt, replace an old identity or reactivate a revoked device.
// The existing signed renewal procedure still must approve and persist it.
export function prepareQuorumEnrollmentPolicy(request,votes,{trusted,rosterPin,quorumPin,state,previousPolicy,approved=false,now=Date.now()}={}){
 check(approved===true);
 const result=verifyNativeEnrollmentQuorum(request,votes,{trusted,rosterPin,quorumPin,now});
 const p=result.policyCandidate;
 check(state?.format==='quantic-relay-state'&&state.version===3&&Array.isArray(state.manifests)&&Array.isArray(state.cryptoProfiles));
 const saved=Date.parse(state.savedAt);check(Number.isFinite(saved)&&saved<=now&&saved>now-30000);
 check(Array.isArray(previousPolicy)&&previousPolicy.length<1024&&previousPolicy.every(x=>x&&typeof x.active==='boolean'&&typeof x.address==='string'&&typeof x.deviceId==='string'));
 // No update/re-enrollment of any pre-existing address (including inactive).
 check(!previousPolicy.some(x=>x.address===p.address||x.deviceId===p.deviceId));
 const m=state.manifests.filter(x=>Array.isArray(x)&&x[0]===p.address),c=state.cryptoProfiles.filter(x=>Array.isArray(x)&&x[0]===p.address);
 check(m.length===1&&m[0].length===2&&c.length===1&&c[0].length===2);
 bindNativeContact({manifest:m[0][1],profile:c[0][1]},{...p,expires:now+15000},now);
 const policy=[...structuredClone(previousPolicy),{...p,active:true}];
 return Object.freeze({status:'quorum-policy-prepared-not-published',labOnly:true,policy,requestDigest:result.requestDigest,
 approvals:result.approvals,remotelyEnrolled:false,mailAuthorized:false});
}
