// Quantic migration multi-relay coordinator — SYNTHETIC LOOPBACK LAB ONLY.
// Two independent relay processes, each with an operator-specific secret.
// A durable local intent makes ambiguous network outcomes recoverable.
// There is NO distributed consensus, no global durable write barrier,
// no quorum cutover and no permission to migrate historical identities.
import {randomBytes,createHash} from "node:crypto";
import {mkdir,open,readFile,rename,rm} from "node:fs/promises";
import {join} from "node:path";
import {verifyMigrationLabMailbox,compareMigrationLabMailboxes} from "../standalone-relay/migration-attestation-lab.ts";

const fail=(ok)=>{if(!ok)throw Error("Multi-relay migration laboratory refused");};
const FORMAT="quantic-migration-multirelay-intent-lab/v1";
const hex32=/^[a-f0-9]{32}$/,hex64=/^[a-f0-9]{64}$/;
const addr=/^[a-z0-9][a-z0-9._-]{2,31}~(?:[a-f0-9]{10}|[a-f0-9]{32})@quantic$/;
const dev=/^d-[a-f0-9]{10}(?:[a-f0-9]{22})?$/;
const sha=x=>createHash("sha256").update(x).digest("hex");
const pathFor=dir=>join(dir,"coordinator-intent.json");
function baseUrl(endpoint){
 fail(typeof endpoint==="string"&&endpoint.length<100);
 const u=new URL(endpoint);
 fail(u.protocol==="http:"&&u.hostname==="127.0.0.1"&&u.port!==""
  &&u.pathname==="/"&&u.search===""&&u.hash===""
  &&u.username===""&&u.password==="");
 return u.origin;
}
function safeParticipants(entries){
 fail(Array.isArray(entries)&&entries.length>=2&&entries.length<=4);
 const relays=new Set(),endpoints=new Set();
 for(const x of entries){
  fail(x&&typeof x==="object"&&hex64.test(x.relayId)
   &&addr.test(x.canonicalAddress)&&dev.test(x.deviceId)
   &&typeof x.operatorSecret==="string"&&x.operatorSecret.length>=32&&x.operatorSecret.length<=256
   &&typeof x.mailboxToken==="string"&&x.mailboxToken.length>=24&&x.mailboxToken.length<=256);
  const e=baseUrl(x.endpoint);
  fail(!relays.has(x.relayId)&&!endpoints.has(e));
  relays.add(x.relayId);endpoints.add(e);
 }
 return entries.map(x=>({...x,endpoint:baseUrl(x.endpoint)}));
}
function verifyIntent(doc,participants){
 fail(doc&&Object.getPrototypeOf(doc)===Object.prototype
  &&doc.format===FORMAT&&doc.version===1&&doc.labOnly===true
  &&hex32.test(doc.transactionId)&&["intent","partially-frozen","fully-frozen","verified","rollback-incomplete","rolled-back"].includes(doc.stage)
  &&Array.isArray(doc.relays)&&doc.relays.length===participants.length);
 for(let i=0;i<participants.length;i++){
  const old=doc.relays[i],now=participants[i];
  fail(old&&Object.getPrototypeOf(old)===Object.prototype
   &&Object.keys(old).every(k=>["endpoint","relayId","canonicalAddress","deviceId","fenceId","evidenceHash"].includes(k))
   &&old.endpoint===now.endpoint&&old.relayId===now.relayId
   &&old.canonicalAddress===now.canonicalAddress&&old.deviceId===now.deviceId
   &&(old.fenceId===null||hex32.test(old.fenceId))
   &&(old.evidenceHash===null||hex64.test(old.evidenceHash)));
 }
 return doc;
}
async function persist(dir,doc){
 await mkdir(dir,{recursive:true,mode:0o700});
 const p=pathFor(dir),t=join(dir,".intent-"+randomBytes(12).toString("hex")+".tmp");
 let handle;
 try{
  handle=await open(t,"wx",0o600);
  await handle.writeFile(JSON.stringify(doc)+"\n","utf8");
  await handle.sync();await handle.close();handle=undefined;
  await rename(t,p);
  // Directory sync is supported on our Linux test runners. On Windows this
  // may be unsupported: no claim of power-loss durability is made.
  if(process.platform!=="win32"){
   const directory=await open(dir,"r");try{await directory.sync();}finally{await directory.close();}
  }
 }catch(e){
  if(handle)await handle.close().catch(()=>{});
  await rm(t,{force:true}).catch(()=>{});
  throw e;
 }
}
// Strict single-writer process lock. A crashed coordinator intentionally
// leaves a stale lock and FAILS CLOSED until an operator verifies the process
// has stopped and manually removes the lock. No automatic stale-lock takeover.
async function withExclusiveCoordinator(dir,action){
 await mkdir(dir,{recursive:true,mode:0o700});
 const file=join(dir,".coordinator-active.lock");
 const h=await open(file,"wx",0o600);
 try{
  await h.writeFile(JSON.stringify({format:"quantic-migration-operation-lock-lab/v1",pid:process.pid})+"\n");
  await h.sync();
  return await action();
 }finally{
  await h.close();
  await rm(file,{force:false});
 }
}
async function readIntent(dir,participants){
 const raw=await readFile(pathFor(dir),"utf8");
 fail(Buffer.byteLength(raw)<=16000);
 return verifyIntent(JSON.parse(raw),participants);
}
async function request(p,path,{method="GET",token=p.operatorSecret}={}){
 const u=p.endpoint+path;
 const res=await fetch(u,{method,redirect:"error",cache:"no-store",
  headers:{"x-quantic-lab-operator":token},
  signal:AbortSignal.timeout(6000)});
 fail(res.status===200&&res.ok);
 const raw=await res.text();
 fail(Buffer.byteLength(raw)<=200000);
 return JSON.parse(raw);
}
async function status(p){
 const result=await request(p,"/api/quantic/lab/fence-status");
 fail(result.labOnly===true&&result.relayId===p.relayId
  &&result.liveRestoreAuthorized===false&&result.legacyDeletionAuthorized===false
  &&(result.fence===null||result.fence?.relayId===p.relayId));
 return result.fence;
}
async function snapshot(p,transactionId,fenceId){
 const nonce=randomBytes(32).toString("base64url");
 const q=new URLSearchParams({handle:p.canonicalAddress,deviceId:p.deviceId,nonce});
 const response=await fetch(p.endpoint+"/api/quantic/lab/migration-snapshot?"+q,
  {method:"GET",redirect:"error",cache:"no-store",
   headers:{authorization:"Bearer "+p.mailboxToken},signal:AbortSignal.timeout(6000)});
 fail(response.ok&&response.status===200);
 const raw=await response.text();fail(Buffer.byteLength(raw)<200000);
 const proof=verifyMigrationLabMailbox(JSON.parse(raw),{
  relayId:p.relayId,canonicalAddress:p.canonicalAddress,deviceId:p.deviceId,
  fenceId,nonce
 });
 fail(proof.fenceId===fenceId);
 return {proof,nonce};
}
function verifyRemoteFence(f,transactionId,expected){
 fail(f&&f.version===1&&f.phase==="frozen"&&f.transactionId===transactionId
  &&hex32.test(f.fenceId)&&(!expected||f.fenceId===expected));
 return f.fenceId;
}
/**
 * Resume-safe all-or-none verification (NOT an atomic distributed commit):
 * - persist intent before contacting any relay
 * - before freeze, preflight that every relay is unfrozen
 * - persist fence id after every verified durable 200
 * - after ambiguous failures, recover by reading transaction-bound status
 * - leave any partial freeze in place until explicitly resumed or rolled back
 * - sign and verify two entire mailbox captures per relay
 * - never store credentials or message content on disk
 */
export async function freezeAndVerifyMultiRelayLab({directory,participants:inputs}){
 fail(typeof directory==="string"&&directory.length>4);
 const participants=safeParticipants(inputs);
 return withExclusiveCoordinator(directory,async()=>{
 let doc;
 try{doc=await readIntent(directory,participants);}
 catch(e){if(e?.code!=="ENOENT")throw e;
  // No prior intent: fail preflight without making any mutations.
  for(const p of participants)fail(await status(p)===null);
  doc={format:FORMAT,version:1,labOnly:true,
   transactionId:randomBytes(16).toString("hex"),stage:"intent",
   relays:participants.map(p=>({endpoint:p.endpoint,relayId:p.relayId,
    canonicalAddress:p.canonicalAddress,deviceId:p.deviceId,
    fenceId:null,evidenceHash:null}))};
  await persist(directory,doc);
 }
 fail(doc.stage!=="rolled-back"&&doc.stage!=="rollback-incomplete");
 for(let i=0;i<participants.length;i++){
  const p=participants[i],r=doc.relays[i];
  const existing=await status(p);
  if(existing){
   const id=verifyRemoteFence(existing,doc.transactionId,r.fenceId);
   if(r.fenceId===null){r.fenceId=id;doc.stage="partially-frozen";await persist(directory,doc);}
  }else{
   fail(r.fenceId===null);
   const response=await request(p,"/api/quantic/lab/freeze?transactionId="+doc.transactionId,{method:"POST"});
   const id=verifyRemoteFence(response.fence,doc.transactionId,null);
   fail(response.labOnly===true&&response.liveRestoreAuthorized===false&&response.legacyDeletionAuthorized===false);
   r.fenceId=id;doc.stage="partially-frozen";await persist(directory,doc);
  }
 }
 doc.stage="fully-frozen";await persist(directory,doc);
 for(let i=0;i<participants.length;i++){
  const p=participants[i],r=doc.relays[i];
  const first=await snapshot(p,doc.transactionId,r.fenceId);
  const second=await snapshot(p,doc.transactionId,r.fenceId);
  const report=compareMigrationLabMailboxes(first.proof,second.proof,{
   relayId:p.relayId,canonicalAddress:p.canonicalAddress,deviceId:p.deviceId,
   firstNonce:first.nonce,secondNonce:second.nonce,fenceId:r.fenceId
  });
  fail(report.fullyEnumeratedStoredMailbox===true&&report.observedSignedSnapshotsStable===true
   &&report.observedAtCapacity===false&&report.remoteQueueReconciled===false);
  verifyRemoteFence(await status(p),doc.transactionId,r.fenceId);
  r.evidenceHash=sha(JSON.stringify([first.proof,second.proof]));
  await persist(directory,doc);
 }
 for(let i=0;i<participants.length;i++)verifyRemoteFence(await status(participants[i]),doc.transactionId,doc.relays[i].fenceId);
 doc.stage="verified";await persist(directory,doc);
 return Object.freeze({status:"synthetic-all-relays-frozen-and-attested",transactionId:doc.transactionId,
  relayCount:doc.relays.length,allFencesVerified:true,
  verifiedEvidenceCount:doc.relays.filter(r=>hex64.test(r.evidenceHash)).length,
  remoteQueueReconciled:false,liveRestoreAuthorized:false,
  legacyDeletionAuthorized:false,labOnly:true});
 });
}
/** An explicit operator rollback, NEVER a migration commit. If a relay is
 * unreachable, report incomplete and leave its fence untouched. The journal
 * permits retry with the same explicit credentials.
 */
export async function rollbackMultiRelayLab({directory,participants:inputs}){
 const participants=safeParticipants(inputs);
 return withExclusiveCoordinator(directory,async()=>{
 const doc=await readIntent(directory,participants);
 fail(doc.stage!=="rolled-back");
 let unresolved=0;
 for(let i=0;i<participants.length;i++){
  const p=participants[i],r=doc.relays[i];
  try{
   const current=await status(p);
   if(current){
    const id=verifyRemoteFence(current,doc.transactionId,r.fenceId);
    fail(r.fenceId!==null||id===r.fenceId);
    const response=await request(p,"/api/quantic/lab/release?fenceId="+id,{method:"POST"});
    fail(response.released===true&&response.liveRestoreAuthorized===false
     &&response.legacyDeletionAuthorized===false);
    fail(await status(p)===null);
   }else fail(r.fenceId===null||hex32.test(r.fenceId));
   r.fenceId=null;r.evidenceHash=null;
  }catch{unresolved++;}
  doc.stage="rollback-incomplete";await persist(directory,doc);
 }
 if(unresolved===0){doc.stage="rolled-back";await persist(directory,doc);}
 return Object.freeze({status:unresolved===0?"synthetic-rollback-complete":"synthetic-rollback-incomplete",
  unresolved,relayCount:participants.length,labOnly:true,
  remoteQueueReconciled:false,liveRestoreAuthorized:false,legacyDeletionAuthorized:false});
 });
}
export async function inspectMultiRelayLab({directory,participants:inputs}){
 const participants=safeParticipants(inputs),doc=await readIntent(directory,participants);
 const states=[];
 for(let i=0;i<participants.length;i++){
  try{
   const current=await status(participants[i]);
   const valid=current===null?doc.relays[i].fenceId===null
    :current.transactionId===doc.transactionId
      &&current.fenceId===doc.relays[i].fenceId
      &&current.relayId===participants[i].relayId;
   states.push({relayId:participants[i].relayId,reachable:true,valid,frozen:current!==null});
  }catch{states.push({relayId:participants[i].relayId,reachable:false,valid:false,frozen:null});}
 }
 return Object.freeze({transactionId:doc.transactionId,stage:doc.stage,states,
  allVerified:doc.stage==="verified"&&states.every(x=>x.valid&&x.frozen),
  labOnly:true,remoteQueueReconciled:false,liveRestoreAuthorized:false,legacyDeletionAuthorized:false});
}
