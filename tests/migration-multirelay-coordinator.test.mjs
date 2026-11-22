import test from "node:test";
import assert from "node:assert/strict";
import {spawn} from "node:child_process";
import {once} from "node:events";
import {generateKeyPairSync,randomBytes,sign} from "node:crypto";
import {mkdtemp,readFile,rm,mkdir,writeFile} from "node:fs/promises";
import {tmpdir} from "node:os";
import {join} from "node:path";
import {fileURLToPath} from "node:url";
import {
 freezeAndVerifyMultiRelayLab,rollbackMultiRelayLab,inspectMultiRelayLab
} from "../lib/quantic/migration-multirelay-coordinator-lab.mjs";

const fixture=fileURLToPath(new URL("./fixtures/migration-fenced-relay-child.mjs",import.meta.url));
const secrets=[randomBytes(48).toString("base64url"),randomBytes(48).toString("base64url")];
const head=token=>({"content-type":"application/json",...(token?{authorization:"Bearer "+token}:{})});
const keypair=()=>({
 enc:generateKeyPairSync("ec",{namedCurve:"prime256v1"}),
 sig:generateKeyPairSync("ec",{namedCurve:"prime256v1"})
});
const ids={alice:keypair(),bob:keypair()};
async function startChild(dir,secret,port=0){
 const child=spawn(process.execPath,["--experimental-transform-types",fixture,dir,String(port)],{
  env:{...process.env,QUANTIC_SYNTHETIC_OPERATOR_SECRET:secret},
  stdio:["ignore","pipe","pipe"],windowsHide:true
 });
 let logs="",buf="";
 const ready=new Promise((resolve,reject)=>{
  child.stderr.on("data",c=>{logs+=c.toString();});
  child.stdout.on("data",chunk=>{
   buf+=chunk.toString();
   if(buf.includes("\n"))try{resolve(JSON.parse(buf.slice(0,buf.indexOf("\n"))));}
   catch(error){reject(error);}
  });
  child.once("error",reject);
  child.once("exit",(code)=>reject(Error("Relay test child quit "+code+" "+logs.slice(-1500))));
 });
 try{
  let timeout;
  const deadline=new Promise((_,reject)=>{timeout=setTimeout(()=>reject(Error("relay startup timeout "+logs.slice(-1000))),22000);timeout.unref();});
  const result=await Promise.race([ready,deadline]).finally(()=>clearTimeout(timeout));
  assert.match(result.relayId,/^[0-9a-f]{64}$/);
  return{child,dir,secret,...result};
 }catch(e){child.kill();throw e;}
}
async function stopChild(node){
 if(!node||node.child.exitCode!==null||node.child.signalCode!==null)return;
 const waiting=once(node.child,"exit");
 node.child.kill("SIGTERM");
 await waiting;
}
async function enroll(node,handle,keys){
 const publicKey=keys.enc.publicKey.export({format:"jwk"});
 const signingPublicKey=keys.sig.publicKey.export({format:"jwk"});
 const authToken=(handle+"-multirelay-synthetic-only-"+node.relayId.slice(0,12)).padEnd(68,"x");
 const c=await fetch(node.url+"/api/quantic/challenge",{method:"POST",headers:head(),
  body:JSON.stringify({handle,publicKey,signingPublicKey})});
 assert.equal(c.status,201);
 const {challenge}=await c.json();
 const signature=sign("sha256",Buffer.from(challenge),{
  key:keys.sig.privateKey,dsaEncoding:"ieee-p1363"
 }).toString("base64");
 const r=await fetch(node.url+"/api/quantic/register",{method:"POST",headers:head(),
  body:JSON.stringify({handle,publicKey,signingPublicKey,authToken,challenge,signature})});
 assert.equal(r.status,201);
 const {canonicalAddress,rootDeviceId}=await r.json();
 return{canonicalAddress,deviceId:rootDeviceId,authToken,publicKey};
}
async function createFixture(){
 const dir=await mkdtemp(join(tmpdir(),"qs-multi-relay-fence-"));
 const nodes=[];
 try{
  nodes.push(await startChild(join(dir,"relay-a"),secrets[0]));
  nodes.push(await startChild(join(dir,"relay-b"),secrets[1]));
  const authors=[],targets=[];
  for(const node of nodes){
   authors.push(await enroll(node,"multi-alice",ids.alice));
   targets.push(await enroll(node,"multi-bobby",ids.bob));
  }
  assert.equal(targets[0].canonicalAddress,targets[1].canonicalAddress);
  assert.equal(targets[0].deviceId,targets[1].deviceId);
  const participants=nodes.map((node,i)=>({
   endpoint:node.url,relayId:node.relayId,
   canonicalAddress:targets[i].canonicalAddress,deviceId:targets[i].deviceId,
   operatorSecret:node.secret,mailboxToken:targets[i].authToken
  }));
  return{dir,nodes,authors,targets,participants,
   cleanup:async()=>{for(const n of nodes)await stopChild(n);await rm(dir,{force:true,recursive:true});}};
 }catch(e){for(const n of nodes)await stopChild(n);await rm(dir,{force:true,recursive:true});throw e;}
}
async function send(node,from,to,id){
 return fetch(node.url+"/api/quantic/send",{method:"POST",headers:head(from.authToken),
  body:JSON.stringify({clientMessageId:id,from:from.canonicalAddress,fromDeviceId:from.deviceId,
   to:to.canonicalAddress,toDeviceId:to.deviceId,
   ciphertext:"synthetic-opaque-"+id,iv:"synthetic-iv",
   ephemeralPublicKey:from.publicKey})});
}
test("two independent relay processes: all freeze, signed mailbox, restart, no ACK, operator rollback",{
 timeout:180000
},async()=>{
 const f=await createFixture();
 try{
  assert.notEqual(f.nodes[0].relayId,f.nodes[1].relayId);
  assert.equal((await send(f.nodes[0],f.authors[0],f.targets[0],"multi-first-0000001")).status,202);
  assert.equal((await send(f.nodes[1],f.authors[1],f.targets[1],"multi-second-000001")).status,202);
  const directory=join(f.dir,"coord-success");
  await mkdir(directory,{recursive:true});
  const lock=join(directory,".coordinator-active.lock");
  await writeFile(lock,"synthetic stale operation lock");
  await assert.rejects(
   freezeAndVerifyMultiRelayLab({directory,participants:f.participants}),
   /EEXIST/,
   "two coordinators must never mutate the same intent simultaneously"
  );
  await rm(lock);
  const result=await freezeAndVerifyMultiRelayLab({directory,participants:f.participants});
  assert.equal(result.status,"synthetic-all-relays-frozen-and-attested");
  assert.equal(result.relayCount,2);assert.equal(result.verifiedEvidenceCount,2);
  assert.equal(result.remoteQueueReconciled,false);
  assert.equal(result.liveRestoreAuthorized,false);
  for(let i=0;i<2;i++)assert.equal(
   (await send(f.nodes[i],f.authors[i],f.targets[i],"multi-blocked-"+i+"-0001")).status,423
  );
  const journal=await readFile(join(directory,"coordinator-intent.json"),"utf8");
  assert.equal(journal.includes(secrets[0]),false);
  assert.equal(journal.includes(secrets[1]),false);
  assert.equal(journal.includes(f.targets[0].authToken),false);
  assert.equal(journal.includes("synthetic-opaque"),false);
  for(let i=0;i<2;i++){
   await stopChild(f.nodes[i]);
   const originalPort=Number(new URL(f.nodes[i].url).port);
   const after=await startChild(f.nodes[i].dir,f.nodes[i].secret,originalPort);
   assert.equal(after.relayId,f.nodes[i].relayId);f.nodes[i]=after;
  }
  assert.equal((await inspectMultiRelayLab({directory,participants:f.participants})).allVerified,true);
  const again=await freezeAndVerifyMultiRelayLab({directory,participants:f.participants});
  assert.equal(again.verifiedEvidenceCount,2);
  const rolledBack=await rollbackMultiRelayLab({directory,participants:f.participants});
  assert.equal(rolledBack.status,"synthetic-rollback-complete");
  assert.equal(rolledBack.legacyDeletionAuthorized,false);
  for(let i=0;i<2;i++)assert.equal(
   (await send(f.nodes[i],f.authors[i],f.targets[i],"multi-resumed-"+i+"-0001")).status,202
  );
 }finally{await f.cleanup();}
});
test("uncertain freeze response, crash-style recovery and interrupted rollback remain fail-closed",{
 timeout:180000
},async()=>{
 const f=await createFixture(),directory=join(f.dir,"coord-recovery");
 const oldFetch=global.fetch;
 try{
  let interrupted=false;
  global.fetch=async(input,options)=>{
   const url=String(input);
   if(!interrupted&&url.startsWith(f.nodes[0].url+"/api/quantic/lab/freeze?")){
    interrupted=true;
    const response=await oldFetch(input,options);
    assert.equal(response.status,200);
    throw Error("Simulated lost 200 freeze response after durable commit");
   }
   return oldFetch(input,options);
  };
  await assert.rejects(
   freezeAndVerifyMultiRelayLab({directory,participants:f.participants}),
   /Simulated lost 200/
  );
  global.fetch=oldFetch;
  const before=await inspectMultiRelayLab({directory,participants:f.participants});
  assert.equal(before.allVerified,false);
  assert.equal(before.states[0].frozen,true);
  assert.equal(before.states[0].valid,false,"missing locally recorded fence is conservative");
  assert.equal(before.states[1].frozen,false);
  // Resume adopts ONLY a fence bearing the original unpredictable transactionId.
  const result=await freezeAndVerifyMultiRelayLab({directory,participants:f.participants});
  assert.equal(result.verifiedEvidenceCount,2);
  let failed=false;
  global.fetch=async(input,options)=>{
   const url=String(input);
   if(!failed&&url.startsWith(f.nodes[1].url+"/api/quantic/lab/release?")){
    failed=true;throw Error("Simulated relay outage during explicit rollback");
   }
   return oldFetch(input,options);
  };
  const partial=await rollbackMultiRelayLab({directory,participants:f.participants});
  global.fetch=oldFetch;
  assert.equal(partial.status,"synthetic-rollback-incomplete");
  assert.equal(partial.unresolved,1);
  const checked=await inspectMultiRelayLab({directory,participants:f.participants});
  assert.equal(checked.states[0].frozen,false);
  assert.equal(checked.states[1].frozen,true);
  assert.equal((await send(f.nodes[1],f.authors[1],f.targets[1],"multi-still-blocked-0001")).status,423);
  const restored=await rollbackMultiRelayLab({directory,participants:f.participants});
  assert.equal(restored.status,"synthetic-rollback-complete");
  assert.equal(restored.liveRestoreAuthorized,false);
  assert.equal((await send(f.nodes[1],f.authors[1],f.targets[1],"multi-now-allowed-0001")).status,202);
 }finally{global.fetch=oldFetch;await f.cleanup();}
});
