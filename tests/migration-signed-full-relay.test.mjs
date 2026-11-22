import test from "node:test";
import assert from "node:assert/strict";
import {generateKeyPairSync,randomBytes,sign} from "node:crypto";
import {mkdtemp,rm} from "node:fs/promises";
import {tmpdir} from "node:os";
import {join} from "node:path";
import {startRelayServer} from "../standalone-relay/server.ts";
import {verifyMigrationLabMailbox,compareMigrationLabMailboxes} from "../standalone-relay/migration-attestation-lab.ts";

const hdr=(token)=>({"content-type":"application/json",...(token?{"authorization":"Bearer "+token}:{})});
async function register(base,handle){
 const encryption=generateKeyPairSync("ec",{namedCurve:"prime256v1"});
 const signing=generateKeyPairSync("ec",{namedCurve:"prime256v1"});
 const publicKey=encryption.publicKey.export({format:"jwk"});
 const signingPublicKey=signing.publicKey.export({format:"jwk"});
 const authToken=(handle+"-synthetic-signed-snapshot-token-").padEnd(64,"x");
 const c=await fetch(base+"/api/quantic/challenge",{method:"POST",headers:hdr(),body:JSON.stringify({handle,publicKey,signingPublicKey})});
 assert.equal(c.status,201);
 const {challenge}=await c.json();
 const signature=sign("sha256",Buffer.from(challenge),{key:signing.privateKey,dsaEncoding:"ieee-p1363"}).toString("base64");
 const r=await fetch(base+"/api/quantic/register",{method:"POST",headers:hdr(),body:JSON.stringify({handle,publicKey,signingPublicKey,authToken,challenge,signature})});
 assert.equal(r.status,201);
 const {canonicalAddress,rootDeviceId}=await r.json();
 return{canonicalAddress,rootDeviceId,authToken,publicKey};
}
async function send(relay,from,to,id){
 const r=await fetch(relay.url+"/api/quantic/send",{method:"POST",headers:hdr(from.authToken),body:JSON.stringify({
  clientMessageId:id,from:from.canonicalAddress,fromDeviceId:from.rootDeviceId,
  to:to.canonicalAddress,toDeviceId:to.rootDeviceId,
  ciphertext:"opaque-synthetic-ciphertext-"+id,iv:"synthetic-iv",
  ephemeralPublicKey:from.publicKey
 })});
 assert.equal(r.status,202,await r.text());
}
const nonce=()=>randomBytes(32).toString("base64url");
async function query(relay,who,challenge,overrides={}){
 const base=relay.url+"/api/quantic/lab/migration-snapshot?";
 const q=new URLSearchParams({handle:who.canonicalAddress,deviceId:who.rootDeviceId,nonce:challenge});
 return fetch(base+q,{method:overrides.method??"GET",headers:{"authorization":"Bearer "+(overrides.authToken??who.authToken),...overrides.headers}});
}
test("signed full retained relay mailbox >100 rows, restart, drift and strict lab isolation",async()=>{
 const dir=await mkdtemp(join(tmpdir(),"qs-full-signed-snapshot-"));
 let relay;
 try{
  relay=await startRelayServer({host:"127.0.0.1",port:0,dataDir:dir,migrationSnapshotLab:true});
  const alice=await register(relay.url,"audit-alice");
  const carol=await register(relay.url,"audit-carol");
  const bob=await register(relay.url,"audit-bobby");
  for(let i=0;i<55;i++)await send(relay,alice,bob,"qs-alice-"+String(i).padStart(6,"0"));
  for(let i=0;i<55;i++)await send(relay,carol,bob,"qs-carol-"+String(i).padStart(6,"0"));
  const ordinary=await fetch(relay.url+"/api/quantic/pull?handle="+encodeURIComponent(bob.canonicalAddress)+"&deviceId="+encodeURIComponent(bob.rootDeviceId),
   {headers:{"authorization":"Bearer "+bob.authToken}});
  assert.equal(ordinary.status,200);
  assert.equal((await ordinary.json()).envelopes.length,100,"legacy endpoint still caps at 100");
  const firstChallenge=nonce();
  const response=await query(relay,bob,firstChallenge);
  assert.equal(response.status,200);
  assert.equal(response.headers.get("access-control-allow-origin"),null);
  assert.equal(response.headers.get("cache-control"),"no-store");
  const first=await response.json();
  const pin=relay.relayId;
  const scope={relayId:pin,canonicalAddress:bob.canonicalAddress,deviceId:bob.rootDeviceId};
  assert.equal(verifyMigrationLabMailbox(first,{...scope,nonce:firstChallenge}).envelopes.length,110);
  assert.equal(first.envelopes.length,110);
  assert.equal(first.receipts.length,0);
  assert.equal(JSON.stringify(first).includes(bob.authToken),false);
  assert.equal(JSON.stringify(first).includes("opaque-synthetic-ciphertext"),false);
  assert.equal((await query(relay,bob,nonce(),{authToken:"invalid-synthetic-token-that-looks-long"})).status,403);
  assert.equal((await query(relay,bob,nonce(),{headers:{origin:"https://evil.invalid"}})).status,403);
  assert.equal((await query(relay,bob,nonce(),{method:"POST"})).status,403);
  assert.throws(()=>verifyMigrationLabMailbox({...first,envelopeRoot:"0".repeat(64)},{...scope,nonce:firstChallenge}));
  assert.throws(()=>verifyMigrationLabMailbox(first,{...scope,relayId:"1".repeat(64),nonce:firstChallenge}));
  assert.throws(()=>verifyMigrationLabMailbox(first,{...scope,nonce:nonce()}));
  assert.throws(()=>verifyMigrationLabMailbox(first,{...scope,nonce:firstChallenge},Date.now()+15*60*1000));
  const forged=structuredClone(first);forged.envelopes[0].recordHash="2".repeat(64);
  assert.throws(()=>verifyMigrationLabMailbox(forged,{...scope,nonce:firstChallenge}));
  await relay.close();relay=null;
  relay=await startRelayServer({host:"127.0.0.1",port:0,dataDir:dir,migrationSnapshotLab:true});
  assert.equal(relay.relayId,pin);
  const secondChallenge=nonce();
  const second=await (await query(relay,bob,secondChallenge)).json();
  const stable=compareMigrationLabMailboxes(first,second,{...scope,firstNonce:firstChallenge,secondNonce:secondChallenge});
  assert.equal(stable.fullyEnumeratedStoredMailbox,true);
  assert.equal(stable.observedSignedSnapshotsStable,true);
  assert.equal(stable.envelopes.before,110);
  assert.equal(stable.envelopes.after,110);
  assert.equal(stable.remoteQueueReconciled,false);
  assert.equal(stable.liveRestoreAuthorized,false);
  assert.equal(stable.legacyDeletionAuthorized,false);
  // The audit never ACKs. All 110 envelopes remain queued after restart.
  const thirdChallenge=nonce();
  await send(relay,alice,bob,"qs-alice-000999");
  const third=await (await query(relay,bob,thirdChallenge)).json();
  const drift=compareMigrationLabMailboxes(second,third,{...scope,firstNonce:secondChallenge,secondNonce:thirdChallenge});
  assert.equal(drift.observedSignedSnapshotsStable,false);
  assert.equal(drift.envelopes.added,1);
  assert.equal(drift.envelopes.after,111);
  assert.equal(drift.remoteQueueReconciled,false);
 }finally{if(relay)await relay.close();await rm(dir,{recursive:true,force:true});}
});
test("signed migration route stays disabled for ordinary relays and refuses public or database-backed opt-in",async()=>{
 const dir=await mkdtemp(join(tmpdir(),"qs-disabled-snapshot-"));
 let relay;
 try{
  await assert.rejects(startRelayServer({host:"0.0.0.0",port:0,dataDir:dir,migrationSnapshotLab:true}),/forbidden/i);
  await assert.rejects(startRelayServer({host:"127.0.0.1",port:0,dataDir:dir,migrationSnapshotLab:true,databaseUrl:"postgres://invalid.local/test"}),/forbidden/i);
  relay=await startRelayServer({host:"127.0.0.1",port:0,dataDir:dir});
  const res=await fetch(relay.url+"/api/quantic/lab/migration-snapshot");
  assert.equal(res.status,404);
 }finally{if(relay)await relay.close();await rm(dir,{recursive:true,force:true});}
});
