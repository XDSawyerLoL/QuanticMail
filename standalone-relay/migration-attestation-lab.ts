// SIGNED SINGLE-RELAY LABORATORY SNAPSHOT ONLY.
// Not a production API, a migration permit, a replicated-relay checkpoint,
// nor a proof of absence of concurrently arriving messages after capture.
import {createHash,createPublicKey,sign,verify,timingSafeEqual} from "node:crypto";
import type {IncomingMessage,ServerResponse} from "node:http";
import {readMigrationLabMailbox} from "../lib/quantic/relay.ts";
import {relayIdForPublicKey,type RelayIdentity} from "./identity.ts";
import {RelayRuntime} from "./runtime.ts";

const FORMAT="quantic-relay-mailbox-snapshot-lab/v1";
const idRE=/^[a-f0-9]{64}$/;
const nonceRE=/^[A-Za-z0-9_-]{24,96}$/;
const hexFence=/^[a-f0-9]{32}$/;
const addressRE=/^[a-z0-9][a-z0-9._-]{2,31}~(?:[a-f0-9]{10}|[a-f0-9]{32})@quantic$/;
const deviceRE=/^d-[a-f0-9]{10}(?:[a-f0-9]{22})?$/;
const MAX=500;
// Refuse pathological full queues rather than hashing hundreds of MiB
// on the relay event loop. Larger queues require a separate streaming design.
const MAX_CAPTURE_BYTES=12*1024*1024;
const check=(ok:unknown)=>{if(!ok)throw Error("Signed relay migration snapshot refused");};
const hash=(s:string)=>createHash("sha256").update(s).digest("hex");
type RowDigest={idHash:string;recordHash:string};
export type SignedMigrationLabSnapshot={
 format:typeof FORMAT;version:1;labOnly:true;
 relayId:string;canonicalAddress:string;deviceId:string;nonce:string;
 fenceId?:string;
 issuedAt:string;queueCapacity:500;receiptCapacity:500;
 envelopes:RowDigest[];receipts:RowDigest[];
 envelopeRoot:string;receiptRoot:string;
 classicalSigningPublicKey:JsonWebKey;p256Signature:string;
};
function digests(rows:Array<{id:string}>):RowDigest[]{
 check(rows.length<=MAX);
 const seen=new Set<string>();
 let processed=0;
 return rows.map(row=>{
  check(row&&Object.getPrototypeOf(row)===Object.prototype
   &&typeof row.id==="string"&&row.id.length>0&&row.id.length<=128
   &&!seen.has(row.id));
  seen.add(row.id);
  const serialized=JSON.stringify(row);
  processed+=Buffer.byteLength(serialized);
  check(processed<=MAX_CAPTURE_BYTES);
  return {idHash:hash("quantic-relay-row-id/v1:"+row.id),
   recordHash:hash("quantic-relay-row/v1:"+serialized)};
 }).sort((a,b)=>a.idHash.localeCompare(b.idHash));
}
function root(rows:RowDigest[],kind:string){
 return hash(JSON.stringify([FORMAT,kind,rows]));
}
function unsigned(proof:SignedMigrationLabSnapshot){
 return {
  format:FORMAT,version:1,labOnly:true,
  relayId:proof.relayId,canonicalAddress:proof.canonicalAddress,
  deviceId:proof.deviceId,nonce:proof.nonce,issuedAt:proof.issuedAt,
  ...(proof.fenceId?{fenceId:proof.fenceId}:{}),
  queueCapacity:500,receiptCapacity:500,
  envelopes:proof.envelopes,receipts:proof.receipts,
  envelopeRoot:proof.envelopeRoot,receiptRoot:proof.receiptRoot,
  classicalSigningPublicKey:proof.classicalSigningPublicKey
 };
}
function validateRows(rows:unknown,kind:string):asserts rows is RowDigest[]{
 if(!Array.isArray(rows)||rows.length>MAX)throw Error("Signed relay migration snapshot refused");
 let previous="";
 for(const row of rows){
  check(row&&Object.getPrototypeOf(row)===Object.prototype&&Object.keys(row).length===2
   &&typeof row.idHash==="string"&&idRE.test(row.idHash)
   &&typeof row.recordHash==="string"&&idRE.test(row.recordHash)
   &&row.idHash>previous);
  previous=row.idHash;
 }
 check(idRE.test(root(rows,kind)));
}
function validateProofShape(x:unknown):asserts x is SignedMigrationLabSnapshot{
 check(x&&typeof x==="object"&&!Array.isArray(x));
 const p=x as SignedMigrationLabSnapshot;
 check(Object.keys(p).length===(p.fenceId===undefined?16:17)
  &&(p.fenceId===undefined||hexFence.test(p.fenceId))&&p.format===FORMAT&&p.version===1&&p.labOnly===true
  &&idRE.test(p.relayId)&&addressRE.test(p.canonicalAddress)&&deviceRE.test(p.deviceId)
  &&nonceRE.test(p.nonce)&&p.queueCapacity===500&&p.receiptCapacity===500
  &&typeof p.issuedAt==="string"&&Number.isFinite(Date.parse(p.issuedAt))
  &&idRE.test(p.envelopeRoot)&&idRE.test(p.receiptRoot));
 validateRows(p.envelopes,"envelopes");validateRows(p.receipts,"receipts");
 check(p.envelopeRoot===root(p.envelopes,"envelopes")
  &&p.receiptRoot===root(p.receipts,"receipts"));
 check(p.classicalSigningPublicKey&&typeof p.classicalSigningPublicKey==="object"
  &&typeof p.p256Signature==="string"&&p.p256Signature.length>=80&&p.p256Signature.length<=132);
}
export function signMigrationLabMailbox(identity:RelayIdentity,records:{
 canonicalAddress:string;deviceId:string;envelopes:Array<{id:string}>;
 receipts:Array<{id:string}>;
},nonce:string,fenceId?:string):SignedMigrationLabSnapshot{
 check(fenceId===undefined||hexFence.test(fenceId));
 check(nonceRE.test(nonce)&&addressRE.test(records.canonicalAddress)&&deviceRE.test(records.deviceId));
 check(relayIdForPublicKey(identity.publicKeyJwk)===identity.relayId);
 const base={
  format:FORMAT as typeof FORMAT,version:1 as const,labOnly:true as const,
  relayId:identity.relayId,canonicalAddress:records.canonicalAddress,
  deviceId:records.deviceId,nonce,issuedAt:new Date().toISOString(),
  ...(fenceId?{fenceId}:{}),
  queueCapacity:500 as const,receiptCapacity:500 as const,
  envelopes:digests(records.envelopes),receipts:digests(records.receipts),
  envelopeRoot:"",receiptRoot:"",
  classicalSigningPublicKey:identity.publicKeyJwk,
  p256Signature:""
 };
 base.envelopeRoot=root(base.envelopes,"envelopes");
 base.receiptRoot=root(base.receipts,"receipts");
 const signature=sign("sha256",Buffer.from(JSON.stringify(unsigned(base))),{
  key:identity.privateKeyPem,dsaEncoding:"ieee-p1363"
 });
 base.p256Signature=signature.toString("base64");
 return base;
}
export function verifyMigrationLabMailbox(value:unknown,expected:{
 relayId:string;canonicalAddress:string;deviceId:string;nonce:string;fenceId?:string;
},now=Date.now()):SignedMigrationLabSnapshot{
 validateProofShape(value);
 check(idRE.test(expected.relayId)&&nonceRE.test(expected.nonce)
  &&value.relayId===expected.relayId
  &&value.canonicalAddress===expected.canonicalAddress
  &&value.deviceId===expected.deviceId&&value.nonce===expected.nonce
   &&(expected.fenceId===undefined||value.fenceId===expected.fenceId)
  &&Math.abs(now-Date.parse(value.issuedAt))<=5*60*1000);
 check(relayIdForPublicKey(value.classicalSigningPublicKey)===expected.relayId);
 const sig=Buffer.from(value.p256Signature,"base64");
 check(sig.length===64&&sig.toString("base64")===value.p256Signature);
 check(verify("sha256",Buffer.from(JSON.stringify(unsigned(value))),{
  key:createPublicKey({key:value.classicalSigningPublicKey,format:"jwk"}),
  dsaEncoding:"ieee-p1363"
 },sig));
 return structuredClone(value);
}
export function compareMigrationLabMailboxes(
 first:unknown,second:unknown,
 scope:{relayId:string;canonicalAddress:string;deviceId:string;firstNonce:string;secondNonce:string;fenceId?:string}
){
 check(scope.firstNonce!==scope.secondNonce);
 const expected={relayId:scope.relayId,canonicalAddress:scope.canonicalAddress,deviceId:scope.deviceId};
 const before=verifyMigrationLabMailbox(first,{...expected,nonce:scope.firstNonce,fenceId:scope.fenceId});
 const after=verifyMigrationLabMailbox(second,{...expected,nonce:scope.secondNonce,fenceId:scope.fenceId});
 check(before.fenceId===after.fenceId);
 const changes=(a:RowDigest[],b:RowDigest[])=>{
  const old=new Map(a.map(x=>[x.idHash,x.recordHash]));
  const next=new Map(b.map(x=>[x.idHash,x.recordHash]));
  let removed=0,added=0,modified=0;
  for(const [id,digest] of old){if(!next.has(id))removed++;else if(next.get(id)!==digest)modified++;}
  for(const id of next.keys())if(!old.has(id))added++;
  return {before:a.length,after:b.length,added,removed,modified,
   unchanged:added===0&&removed===0&&modified===0};
 };
 const envelopes=changes(before.envelopes,after.envelopes);
 const receipts=changes(before.receipts,after.receipts);
 return Object.freeze({
  fullyEnumeratedStoredMailbox:true,
  observedSignedSnapshotsStable:envelopes.unchanged&&receipts.unchanged,
  observedAtCapacity:before.envelopes.length===MAX||after.envelopes.length===MAX
   ||before.receipts.length===MAX||after.receipts.length===MAX,
  envelopes,receipts,
  // Stability between two captures cannot exclude a write immediately after.
  // No real account migration, cross-relay quorum or atomic write fence exists.
  remoteQueueReconciled:false,liveRestoreAuthorized:false,
  legacyDeletionAuthorized:false,labOnly:true
 });
}
/**
 * Derive the only remote-audit facts allowed in the existing encrypted,
 * append-only migration journal. Both signatures MUST verify first.
 * Stable captures can never set remoteQueueReconciled or authorize cutover.
 */
export function signedMigrationLabAuditFacts(
 first:unknown,second:unknown,
 scope:{relayId:string;canonicalAddress:string;deviceId:string;firstNonce:string;secondNonce:string;fenceId?:string}
){
 const report=compareMigrationLabMailboxes(first,second,scope);
 const before=verifyMigrationLabMailbox(first,{
  relayId:scope.relayId,canonicalAddress:scope.canonicalAddress,
  deviceId:scope.deviceId,nonce:scope.firstNonce,fenceId:scope.fenceId
 });
 const after=verifyMigrationLabMailbox(second,{
  relayId:scope.relayId,canonicalAddress:scope.canonicalAddress,
  deviceId:scope.deviceId,nonce:scope.secondNonce,fenceId:scope.fenceId
 });
 return Object.freeze({
  relayIdSha256:hash(scope.relayId),
  observedWindowSha256:hash(JSON.stringify([before,after])),
  observedRelayWindowStable:report.observedSignedSnapshotsStable,
  observedRelayWindowNotAtCap:!report.observedAtCapacity,
  pendingIncomingVisible:report.envelopes.after,
  pendingReceiptsVisible:report.receipts.after,
  // Deliberately no permission to call ACK, activate prekeys or migrate.
 });
}
/** Isolated loopback-only laboratory routes. All freeze/release operations
 * require an independent out-of-band operator secret, never a mailbox bearer.
 * The mutation fence is committed to the same durable store as the queues.
 */
export function createMigrationLabSnapshotHandler(
 runtime:RelayRuntime,identity:RelayIdentity,operatorSecret?:string
){
 const correctOperator=(supplied:string|undefined)=>{
  if(!operatorSecret||!supplied||supplied.length<32||supplied.length>256)return false;
  return timingSafeEqual(
   createHash("sha256").update(supplied).digest(),
   createHash("sha256").update(operatorSecret).digest()
  );
 };
 return async (req:IncomingMessage,res:ServerResponse):Promise<boolean>=>{
  const url=new URL(req.url??"/","http://127.0.0.1");
  const base="/api/quantic/lab/";
  if(!url.pathname.startsWith(base))return false;
  res.setHeader("Cache-Control","no-store");
  res.setHeader("Content-Type","application/json; charset=utf-8");
  const reply=(status:number)=>{res.statusCode=status;res.end(JSON.stringify({error:"Migration laboratory operation refused"}));};
  if(req.socket.remoteAddress!=="127.0.0.1"||
   req.headers.origin!==undefined||req.headers["sec-fetch-site"]!==undefined||
   req.headers["transfer-encoding"]!==undefined){reply(403);return true;}
  const operation=url.pathname.slice(base.length);
  try{
   if(operation==="migration-snapshot"){
    check(req.method==="GET");
    const q=url.searchParams;
    check([...q.keys()].length===3&&q.has("handle")&&q.has("deviceId")&&q.has("nonce")
     &&q.getAll("handle").length===1&&q.getAll("deviceId").length===1&&q.getAll("nonce").length===1);
    const token=req.headers.authorization;
    if(typeof token!=="string"||!token.startsWith("Bearer ")
     ||token.length<31||token.length>263)throw Error("Signed relay migration snapshot refused");
    const handle=q.get("handle")??"",deviceId=q.get("deviceId")??"",nonce=q.get("nonce")??"";
    check(addressRE.test(handle)&&deviceRE.test(deviceId)&&nonceRE.test(nonce));
    const proof=await runtime.readMigrationLab(()=>signMigrationLabMailbox(
     identity,readMigrationLabMailbox(handle,token.slice(7),deviceId),
     nonce,runtime.getMigrationLabFence()?.fenceId
    ));
    res.statusCode=200;res.end(JSON.stringify(proof));return true;
   }
   // An authenticated mailbox holder MUST NOT be allowed to freeze the
   // entire relay. Laboratory administration uses a distinct strong token.
   const operator=req.headers["x-quantic-lab-operator"];
   check(typeof operator==="string"&&correctOperator(operator));
   check(!req.headers["content-length"]||req.headers["content-length"]==="0");
   if(operation==="fence-status"){
    check(req.method==="GET"&&url.searchParams.size===0);
    res.statusCode=200;res.end(JSON.stringify({
     labOnly:true,relayId:identity.relayId,
     fence:runtime.getMigrationLabFence(),
     liveRestoreAuthorized:false,legacyDeletionAuthorized:false
    }));return true;
   }
   if(operation==="freeze"){
    check(req.method==="POST"&&url.searchParams.size===0);
    const fence=await runtime.freezeMigrationLab(identity.relayId);
    res.statusCode=200;res.end(JSON.stringify({
     labOnly:true,fence,liveRestoreAuthorized:false,legacyDeletionAuthorized:false
    }));return true;
   }
   if(operation==="release"){
    check(req.method==="POST"&&url.searchParams.size===1);
    const fenceId=url.searchParams.get("fenceId")??"";
    check(hexFence.test(fenceId));
    await runtime.releaseMigrationLab(fenceId);
    res.statusCode=200;res.end(JSON.stringify({
     labOnly:true,released:true,liveRestoreAuthorized:false,legacyDeletionAuthorized:false
    }));return true;
   }
   reply(404);
  }catch{reply(403);}
  return true;
 };
}
