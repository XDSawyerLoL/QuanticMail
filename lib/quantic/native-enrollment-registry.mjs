// Native-only enrollment registry. No legacy identity or authentication grant.
import {createHash,createPublicKey,randomBytes,sign,verify,timingSafeEqual} from 'node:crypto';
import {verifyNativeEnrollmentQuorum} from '../../desktop/native-enrollment-quorum.mjs';
import {verifyNativeEnrollmentRequest} from '../../desktop/native-enrollment-claim.mjs';
import {canonicalManifestText} from './manifest-core.mjs';
import {canonicalCryptoProfileText} from './crypto-profile-core.mjs';
import {bindNativeContact} from './native-identity-bridge.mjs';
const check=x=>{if(!x)throw Error('Native enrollment refused');};
const hex=/^[a-f0-9]{64}$/,addr=/^[a-z0-9][a-z0-9._-]{2,31}~[a-f0-9]{32}@quantic$/,dev=/^d-[a-f0-9]{32}$/;
const hash=x=>createHash('sha256').update(x).digest('hex');
const tokenOK=x=>typeof x==='string'&&/^[A-Za-z0-9_-]{43}$/.test(x)&&Buffer.from(x,'base64url').length===32&&Buffer.from(x,'base64url').toString('base64url')===x;
const transcript=(digest,tokenHash)=>Buffer.from(JSON.stringify(['quantic-native-mailbox-credential-lab/v1',digest,tokenHash]));
const scope=(a,d)=>a+'#'+d;
const fields=['address','deviceId','rootPin','pqRootPin','manifestSequence','profileSequence','manifestDigest','profileDigest','requestDigest','tokenHash','createdAt'];
let rows=new Map();
export function makeNativeEnrollmentCredential(request,votes,options,controllerKey){
 const q=verifyNativeEnrollmentQuorum(request,votes,options);
 check(controllerKey?.type==='private'&&controllerKey.asymmetricKeyType==='ed25519');
 const pub=createPublicKey(controllerKey).export({type:'spki',format:'der'});
 check(pub.subarray(12).toString('base64url')===request.controllerPublic);
 const token=randomBytes(32).toString('base64url'),tokenHash=hash(token);
 const signature=sign(null,transcript(q.requestDigest,tokenHash),controllerKey).toString('base64url');
 return {token,credential:{tokenHash,signature}};
}
export function validateNativeEnrollmentRows(input){
 check(Array.isArray(input)&&input.length<=1024);
 const seen=new Set(),addresses=new Set(),devices=new Set();
 return input.map(r=>{
  check(r&&Object.keys(r).length===fields.length&&fields.every(k=>Object.hasOwn(r,k))&&addr.test(r.address)&&dev.test(r.deviceId));
  check(['rootPin','pqRootPin','manifestDigest','profileDigest','requestDigest','tokenHash'].every(k=>typeof r[k]==='string'&&hex.test(r[k])));
  check(r.manifestSequence===1&&r.profileSequence===1&&Number.isSafeInteger(r.createdAt)&&r.createdAt>0);
  const k=scope(r.address,r.deviceId);check(!seen.has(k)&&!addresses.has(r.address)&&!devices.has(r.deviceId));
  seen.add(k);addresses.add(r.address);devices.add(r.deviceId);
  return Object.fromEntries(fields.map(k=>[k,r[k]]));
 });
}
export function nativeEnrollmentEntries(){return structuredClone([...rows.values()]);}
export function restoreNativeEnrollments(input){rows=new Map(validateNativeEnrollmentRows(input).map(r=>[scope(r.address,r.deviceId),r]));}
export function authenticateNativeEnrollment(address,device,token){
 const row=rows.get(scope(address,device));
 check(row&&tokenOK(token)&&timingSafeEqual(Buffer.from(row.tokenHash,'hex'),Buffer.from(hash(token),'hex')));
 return {canonicalAddress:row.address,deviceId:row.deviceId};
}
export function assertNativeEnrollmentCheckpoint(address,device,checkpoint){
 const r=rows.get(scope(address,device));check(r&&checkpoint&&['address','deviceId','rootPin','pqRootPin','manifestSequence','profileSequence','manifestDigest','profileDigest'].every(k=>r[k]===checkpoint[k]));
}
export function verifyStoredNativeEnrollmentBindings(input,manifests,profiles,now=Date.now()){
 const entries=validateNativeEnrollmentRows(input);
 for(const r of entries){
  const m=manifests.filter(([a])=>a===r.address),p=profiles.filter(([a])=>a===r.address);
  check(m.length===1&&p.length===1);
  bindNativeContact({manifest:m[0][1],profile:p[0][1]},{...r,expires:now+15000},now);
 }
 return entries;
}
export function isNativeEnrollmentAddress(address){return [...rows.values()].some(r=>r.address===address);}
export function prepareNativeEnrollmentPublication(state,request,votes,credential,options){
 const now=options.now??Date.now();
 check(options.approved===true&&state?.format==='quantic-relay-state'&&state.version===3);
 const quorum=verifyNativeEnrollmentQuorum(request,votes,{...options,now});
 const claim=verifyNativeEnrollmentRequest(request,{quorumPin:options.quorumPin,now});
 check(credential&&Object.keys(credential).length===2&&hex.test(credential.tokenHash)&&typeof credential.signature==='string'&&/^[A-Za-z0-9_-]{86}$/.test(credential.signature));
 const publicDER=Buffer.concat([Buffer.from('302a300506032b6570032100','hex'),Buffer.from(request.controllerPublic,'base64url')]);
 const pub=createPublicKey({key:publicDER,type:'spki',format:'der'});
 const sig=Buffer.from(credential.signature,'base64url');
 check(sig.toString('base64url')===credential.signature&&verify(null,transcript(quorum.requestDigest,credential.tokenHash),pub,sig));
 const a=claim.address,d=claim.deviceId,previous=validateNativeEnrollmentRows(state.nativeEnrollments??[]);
 // No alias insertion or legacy authentication credentials. No overwriting any
 // identity, device, tombstone, manifest or previously enrolled address.
 check(!previous.some(r=>r.address===a||r.deviceId===d||r.tokenHash===credential.tokenHash));
 for(const key of ['identities','devices','manifests','cryptoProfiles']){
  check(Array.isArray(state[key])&&!state[key].some(([k,v])=>k===a||k===scope(a,d)||v?.canonicalAddress===a||v?.deviceId===d));
 }
 check(Array.isArray(state.aliases)&&!state.aliases.some(([,values])=>Array.isArray(values)&&values.includes(a)));
 const {active,...p}=quorum.policyCandidate;
 const m=request.claim.manifest,profile=request.claim.profile;
 // Persist only canonical public fields; discard all unverified extra data.
 const manifest={format:m.format,version:m.version,payload:JSON.parse(canonicalManifestText(m.payload)),signature:m.signature};
 const cryptoProfile={format:profile.format,version:profile.version,payload:JSON.parse(canonicalCryptoProfileText(profile.payload)),signatures:{p256:profile.signatures.p256,mlDsa65Self:profile.signatures.mlDsa65Self}};
 bindNativeContact({manifest,profile:cryptoProfile},{...p,expires:now+15000},now);
 const row={...p,requestDigest:quorum.requestDigest,tokenHash:credential.tokenHash,createdAt:now};
 const next=structuredClone(state);
 next.nativeEnrollments=validateNativeEnrollmentRows([...previous,row]);
 next.manifests.push([a,manifest]);next.cryptoProfiles.push([a,cryptoProfile]);
 return {state:next,report:{status:'native-enrollment-persisted-pending-checkpoints',address:a,deviceId:d,requestDigest:quorum.requestDigest,labOnly:true,mailAuthorized:false}};
}
// Minimal authenticated operator snapshot; never include bearer hashes,
// legacy accounts, mailbox ciphertext, message metadata or private keys.
export function publicNativeEnrollmentSnapshot(state){
 const list=validateNativeEnrollmentRows(state.nativeEnrollments??[]);
 const addresses=new Set(list.map(r=>r.address));
 return {format:'quantic-relay-state',version:3,savedAt:state.savedAt,
 manifests:state.manifests.filter(([a])=>addresses.has(a)),cryptoProfiles:state.cryptoProfiles.filter(([a])=>addresses.has(a))};
}
