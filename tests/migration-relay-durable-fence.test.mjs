import test from "node:test";
import assert from "node:assert/strict";
import {generateKeyPairSync,randomBytes,sign} from "node:crypto";
import {mkdtemp,rm} from "node:fs/promises";
import {tmpdir} from "node:os";
import {join} from "node:path";
import {startRelayServer} from "../standalone-relay/server.ts";
import {verifyMigrationLabMailbox,compareMigrationLabMailboxes} from "../standalone-relay/migration-attestation-lab.ts";

const operator=randomBytes(48).toString("base64url");
const headers=token=>({"content-type":"application/json",...(token?{authorization:"Bearer "+token}:{})});
const challenge=()=>randomBytes(32).toString("base64url");

async function register(base,handle){
 const e=generateKeyPairSync("ec",{namedCurve:"prime256v1"});
 const s=generateKeyPairSync("ec",{namedCurve:"prime256v1"});
 const publicKey=e.publicKey.export({format:"jwk"});
 const signingPublicKey=s.publicKey.export({format:"jwk"});
 const authToken=(handle+"-synthetic-recovery-only-token-").padEnd(64,"x");
 const c=await fetch(base+"/api/quantic/challenge",{method:"POST",headers:headers(),body:JSON.stringify({handle,publicKey,signingPublicKey})});
 assert.equal(c.status,201);
 const {challenge:ch}=await c.json();
 const signature=sign("sha256",Buffer.from(ch),{key:s.privateKey,dsaEncoding:"ieee-p1363"}).toString("base64");
 const r=await fetch(base+"/api/quantic/register",{method:"POST",headers:headers(),body:JSON.stringify({handle,publicKey,signingPublicKey,authToken,challenge:ch,signature})});
 assert.equal(r.status,201);
 const {canonicalAddress,rootDeviceId}=await r.json();
 return{canonicalAddress,deviceId:rootDeviceId,authToken,publicKey};
}
async function send(relay,from,to,id){
 return fetch(relay.url+"/api/quantic/send",{method:"POST",headers:headers(from.authToken),
  body:JSON.stringify({clientMessageId:id,from:from.canonicalAddress,fromDeviceId:from.deviceId,
   to:to.canonicalAddress,toDeviceId:to.deviceId,ciphertext:"synthetic-encrypted-"+id,
   iv:"synthetic-iv",ephemeralPublicKey:from.publicKey})});
}
async function admin(relay,op,{id,secret=operator,method}={}){
 const route=relay.url+"/api/quantic/lab/"+op+(id?"?fenceId="+id:"");
 return fetch(route,{method:method??(op==="fence-status"?"GET":"POST"),
  headers:{"x-quantic-lab-operator":secret}});
}
async function snapshot(relay,who,nonce){
 const q=new URLSearchParams({handle:who.canonicalAddress,deviceId:who.deviceId,nonce});
 const r=await fetch(relay.url+"/api/quantic/lab/migration-snapshot?"+q,{
  headers:{"authorization":"Bearer "+who.authToken}});
 assert.equal(r.status,200);
 return r.json();
}
test("durable isolated write fence closes all other routes and survives restart, with signed snapshots and operator rollback",async()=>{
 const dataDir=await mkdtemp(join(tmpdir(),"quantic-fenced-lab-"));
 let relay=null;
 const opts={host:"127.0.0.1",port:0,dataDir,migrationSnapshotLab:true,migrationLabOperatorSecret:operator};
 try{
  relay=await startRelayServer(opts);
  const alice=await register(relay.url,"fence-alice");
  const bob=await register(relay.url,"fence-bobby");
  assert.equal((await send(relay,alice,bob,"fence-original-0001")).status,202);
  const relayId=relay.relayId;
  assert.equal((await admin(relay,"freeze",{secret:"z".repeat(48)})).status,403);
  assert.equal((await admin(relay,"fence-status",{secret:"z".repeat(48)})).status,403);
  assert.equal((await admin(relay,"release",{id:"0".repeat(32)})).status,403);
  const frozenResponse=await admin(relay,"freeze");
  assert.equal(frozenResponse.status,200);
  const frozen=await frozenResponse.json();
  assert.equal(frozen.labOnly,true);
  assert.equal(frozen.liveRestoreAuthorized,false);
  assert.equal(frozen.legacyDeletionAuthorized,false);
  const fenceId=frozen.fence.fenceId;
  assert.match(fenceId,/^[0-9a-f]{32}$/);
  assert.equal(frozen.fence.relayId,relayId);
  assert.equal((await admin(relay,"freeze")).status,403,"already frozen cannot rotate");
  assert.equal((await send(relay,alice,bob,"fence-forbidden-0002")).status,423);
  const ack=await fetch(relay.url+"/api/quantic/ack",{method:"POST",headers:headers(bob.authToken),
   body:JSON.stringify({handle:bob.canonicalAddress,deviceId:bob.deviceId,ids:[]})});
  assert.equal(ack.status,423);
  const pull=await fetch(relay.url+"/api/quantic/pull?handle="+encodeURIComponent(bob.canonicalAddress),
   {headers:{authorization:"Bearer "+bob.authToken}});
  assert.equal(pull.status,423);
  const firstNonce=challenge(),first=await snapshot(relay,bob,firstNonce);
  assert.equal(first.fenceId,fenceId);
  const scope={relayId,canonicalAddress:bob.canonicalAddress,deviceId:bob.deviceId};
  assert.equal(verifyMigrationLabMailbox(first,{...scope,nonce:firstNonce,fenceId}).envelopes.length,1);
  assert.throws(()=>verifyMigrationLabMailbox(first,{...scope,nonce:firstNonce,fenceId:"f".repeat(32)}));
  await relay.close();relay=null;
  await assert.rejects(startRelayServer({host:"127.0.0.1",port:0,dataDir}),
   /Frozen lab relay cannot restart/);
  relay=await startRelayServer(opts);
  assert.equal(relay.relayId,relayId);
  const statusResponse=await admin(relay,"fence-status");
  assert.equal(statusResponse.status,200);
  const status=await statusResponse.json();
  assert.equal(status.fence.fenceId,fenceId);
  assert.equal((await send(relay,alice,bob,"fence-forbidden-0003")).status,423);
  const secondNonce=challenge(),second=await snapshot(relay,bob,secondNonce);
  const compared=compareMigrationLabMailboxes(first,second,{
   ...scope,firstNonce,secondNonce,fenceId
  });
  assert.equal(compared.fullyEnumeratedStoredMailbox,true);
  assert.equal(compared.observedSignedSnapshotsStable,true);
  assert.equal(compared.envelopes.after,1);
  assert.equal(compared.remoteQueueReconciled,false);
  assert.equal(compared.liveRestoreAuthorized,false);
  assert.equal(compared.legacyDeletionAuthorized,false);
  assert.equal((await admin(relay,"release",{id:"f".repeat(32)})).status,403);
  assert.equal((await admin(relay,"release",{id:fenceId,secret:"X".repeat(48)})).status,403);
  assert.equal((await send(relay,alice,bob,"fence-forbidden-0004")).status,423);
  const released=await admin(relay,"release",{id:fenceId});
  assert.equal(released.status,200);
  assert.equal((await released.json()).legacyDeletionAuthorized,false);
  assert.equal((await admin(relay,"fence-status").then(x=>x.json())).fence,null);
  assert.equal((await send(relay,alice,bob,"fence-after-rollback-0005")).status,202);
  const post=await snapshot(relay,bob,challenge());
  assert.equal(post.fenceId,undefined);
  assert.equal(post.envelopes.length,2,"frozen send never reached queue");
  await relay.close();relay=null;
  relay=await startRelayServer(opts);
  assert.equal((await admin(relay,"fence-status").then(x=>x.json())).fence,null);
  assert.equal((await send(relay,alice,bob,"fence-after-restart-0006")).status,202);
 }finally{if(relay)await relay.close();await rm(dataDir,{recursive:true,force:true});}
});
test("operator secret cannot enable laboratory fence on public or production-configured relay",async()=>{
 const dir=await mkdtemp(join(tmpdir(),"quantic-fence-disabled-"));
 try{
  await assert.rejects(startRelayServer({host:"0.0.0.0",port:0,dataDir:dir,
   migrationSnapshotLab:true,migrationLabOperatorSecret:operator}),/forbidden/i);
  await assert.rejects(startRelayServer({host:"127.0.0.1",port:0,dataDir:dir,
   migrationSnapshotLab:true,migrationLabOperatorSecret:operator,databaseUrl:"postgres://invalid/test"}),/forbidden/i);
  await assert.rejects(startRelayServer({host:"127.0.0.1",port:0,dataDir:dir,
   migrationLabOperatorSecret:operator}),/Invalid isolated migration/i);
  await assert.rejects(startRelayServer({host:"127.0.0.1",port:0,dataDir:dir,
   migrationSnapshotLab:true,migrationLabOperatorSecret:"1234"}),/Invalid isolated migration/i);
 }finally{await rm(dir,{recursive:true,force:true});}
});
