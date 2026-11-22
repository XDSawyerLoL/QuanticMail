// SIGNED SINGLE-RELAY LABORATORY SNAPSHOT ONLY.
// Not a production API, a migration permit, a replicated-relay checkpoint,
// nor a proof of absence of concurrently arriving messages after capture.
import {createHash,createPublicKey,sign,verify} from "node:crypto";
import type {IncomingMessage,ServerResponse} from "node:http";
import {readMigrationLabMailbox} from "../lib/quantic/relay.ts";
import {relayIdForPublicKey,type RelayIdentity} from "./identity.ts";
import {RelayRuntime} from "./runtime.ts";

const FORMAT="quantic-relay-mailbox-snapshot-lab/v1";
const idRE=/^[a-f0-9]{64}$/;
const nonceRE=/^[A-Za-z0-9_-]{24,96}$/;
const addressRE=/^[a-z0-9][a-z0-9._-]{2,31}~(?:[a-f0-9]{10}|[a-f0-9]{32})@quantic$/;
const deviceRE=/^d-[a-f0-9]{10}(?:[a-f0-9]{22})?$/;
const MAX=500;
const check=(ok:unknown)=>{if(!ok)throw Error("Signed relay migration snapshot refused");};
const hash=(s:string)=>createHash("sha256").update(s).digest("hex");
type RowDigest={idHash:string;recordHash:string};
export type SignedMigrationLabSnapshot={
 format:typeof FORMAT;version:1;labOnly:true;
 relayId:string;canonicalAddress:string;deviceId:string;nonce:string;
 issuedAt:string;queueCapacity:500;receiptCapacity:500;
 envelopes:RowDigest[];receipts:RowDigest[];
 envelopeRoot:string;receiptRoot:string;
 classicalSigningPublicKey:JsonWebKey;p256Signature:string;
};
function digests(rows:Array<{id:string}>):RowDigest[]{
 check(rows.length<=MAX);
 const seen=new Set<string>();
 return rows.map(row=>{
  check(row&&Object.getPrototypeOf(row)===Object.prototype
   &&typeof row.id==="string"&&row.id.length>0&&row.id.length<=128
   &&!seen.has(row.id));
  seen.add(row.id);
  return {idHash:hash("quantic-relay-row-id/v1:"+row.id),
   recordHash:hash("quantic-relay-row/v1:"+JSON.stringify(row))};
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
  queueCapacity:500,receiptCapacity:500,
  envelopes:proof.envelopes,receipts:proof.receipts,
  envelopeRoot:proof.envelopeRoot,receiptRoot:proof.receiptRoot,
  classicalSigningPublicKey:proof.classicalSigningPublicKey
 };
}
function validateRows(rows:unknown,kind:string):asserts rows is RowDigest[]{
 check(Array.isArray(rows)&&rows.length<=MAX);
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
 check(Object.keys(p).length===16&&p.format===FORMAT&&p.version===1&&p.labOnly===true
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
},nonce:string):SignedMigrationLabSnapshot{
 check(nonceRE.test(nonce)&&addressRE.test(records.canonicalAddress)&&deviceRE.test(records.deviceId));
 check(relayIdForPublicKey(identity.publicKeyJwk)===identity.relayId);
 const base={
  format:FORMAT as typeof FORMAT,version:1 as const,labOnly:true as const,
  relayId:identity.relayId,canonicalAddress:records.canonicalAddress,
  deviceId:records.deviceId,nonce,issuedAt:new Date().toISOString(),
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
 relayId:string;canonicalAddress:string;deviceId:string;nonce:string;
},now=Date.now()):SignedMigrationLabSnapshot{
 validateProofShape(value);
 check(idRE.test(expected.relayId)&&nonceRE.test(expected.nonce)
  &&value.relayId===expected.relayId
  &&value.canonicalAddress===expected.canonicalAddress
  &&value.deviceId===expected.deviceId&&value.nonce===expected.nonce
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
 scope:{relayId:string;canonicalAddress:string;deviceId:string;firstNonce:string;secondNonce:string}
){
 check(scope.firstNonce!==scope.secondNonce);
 const expected={relayId:scope.relayId,canonicalAddress:scope.canonicalAddress,deviceId:scope.deviceId};
 const before=verifyMigrationLabMailbox(first,{...expected,nonce:scope.firstNonce});
 const after=verifyMigrationLabMailbox(second,{...expected,nonce:scope.secondNonce});
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
/** Never exposed on public or PostgreSQL relay instances. Enforces bearer
 * authentication and exact loopback source, no CORS/Origin nor redirects.
 * One synchronous runtime.read operation snapshots BOTH queues atomically
 * relative to this process's serialized mutations.
 */
export function createMigrationLabSnapshotHandler(runtime:RelayRuntime,identity:RelayIdentity){
 return async (req:IncomingMessage,res:ServerResponse):Promise<boolean>=>{
  const url=new URL(req.url??"/","http://127.0.0.1");
  if(url.pathname!=="/api/quantic/lab/migration-snapshot")return false;
  res.setHeader("Cache-Control","no-store");
  res.setHeader("Content-Type","application/json; charset=utf-8");
  const reply=(status:number)=>{res.statusCode=status;res.end(JSON.stringify({error:"Migration laboratory snapshot refused"}));};
  if(req.method!=="GET"||req.socket.remoteAddress!=="127.0.0.1"||
   req.headers.origin!==undefined||req.headers["sec-fetch-site"]!==undefined||
   req.headers["transfer-encoding"]!==undefined){reply(403);return true;}
  try{
   const q=url.searchParams;
   check([...q.keys()].length===3&&q.has("handle")&&q.has("deviceId")&&q.has("nonce")
    &&q.getAll("handle").length===1&&q.getAll("deviceId").length===1&&q.getAll("nonce").length===1);
   const token=req.headers.authorization;
   check(typeof token==="string"&&token.startsWith("Bearer ")
    &&token.length>=31&&token.length<=263);
   const handle=q.get("handle")??"",deviceId=q.get("deviceId")??"",nonce=q.get("nonce")??"";
   check(addressRE.test(handle)&&deviceRE.test(deviceId)&&nonceRE.test(nonce));
   // No await or network access inside the synchronous capture callback.
   const proof=await runtime.read(()=>signMigrationLabMailbox(
    identity,readMigrationLabMailbox(handle,token.slice(7),deviceId),nonce
   ));
   res.statusCode=200;res.end(JSON.stringify(proof));
  }catch{reply(403);}
  return true;
 };
}
