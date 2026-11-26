import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,sign,createHash,randomBytes} from 'node:crypto';
import {mkdtemp,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {startRelayServer} from '../standalone-relay/server.ts';
import {captureLoopbackRelayObservation,reconcileRelayObservationLab} from '../lib/quantic/migration-relay-observation-lab.mjs';
import {appendMigrationAuditLabRecord} from '../lib/quantic/migration-audit-journal-lab.mjs';
const headers=token=>({'content-type':'application/json',...(token?{authorization:'Bearer '+token}:{})});
async function account(base,handle){
 const encryption=generateKeyPairSync('ec',{namedCurve:'prime256v1'});
 const signing=generateKeyPairSync('ec',{namedCurve:'prime256v1'});
 const publicKey=encryption.publicKey.export({format:'jwk'});
 const signingPublicKey=signing.publicKey.export({format:'jwk'});
 const token=(handle+'-readonly-recovery-laboratory-token-').padEnd(60,'x');
 const first=await fetch(base+'/api/quantic/challenge',{method:'POST',headers:headers(),body:JSON.stringify({handle,publicKey,signingPublicKey})});
 assert.equal(first.status,201);
 const {challenge}=await first.json();
 const signature=sign('sha256',Buffer.from(challenge,'utf8'),{key:signing.privateKey,dsaEncoding:'ieee-p1363'}).toString('base64');
 const registered=await fetch(base+'/api/quantic/register',{method:'POST',headers:headers(),body:JSON.stringify({handle,publicKey,signingPublicKey,authToken:token,challenge,signature})});
 assert.equal(registered.status,201);
 const {canonicalAddress,rootDeviceId}=await registered.json();
 return {canonicalAddress,rootDeviceId,token,publicKey};
}
function historical(){
 return {
  messages:[{id:'old-inbound-1',direction:'in',body:'synthetic historic'}],
  contacts:[{handle:'alice',address:'synthetic@example.invalid'}],
  prekeys:[{preKeyId:'p1',state:'claimed',privateKey:{d:'historical-only'}}],
  outbox:[{id:'client-message-0001',ciphertext:'opaque-not-replayed'}]
 };
}
test('real durable loopback relay: read-only pending envelope audit survives relay restart; detects new arrivals',async()=>{
 const folder=await mkdtemp(join(tmpdir(),'quantic-relay-migration-audit-'));let relay;
 try{
  relay=await startRelayServer({host:'127.0.0.1',port:0,dataDir:folder});
  const alice=await account(relay.url,'audit-alice'),bob=await account(relay.url,'audit-bob');
  async function send(id){
   const r=await fetch(relay.url+'/api/quantic/send',{method:'POST',headers:headers(alice.token),
    body:JSON.stringify({clientMessageId:id,from:alice.canonicalAddress,
     fromDeviceId:alice.rootDeviceId,to:bob.canonicalAddress,toDeviceId:bob.rootDeviceId,
     ciphertext:'synthetic-encrypted-envelope-'+id,iv:'synthetic-iv',ephemeralPublicKey:alice.publicKey})});
   assert.equal(r.status,202);
  }
  const observed=()=>captureLoopbackRelayObservation({endpoint:relay.url,
   canonicalAddress:bob.canonicalAddress,deviceId:bob.rootDeviceId,authToken:bob.token,relayId:relay.relayId});
  await send('client-message-0001');
  const before=await observed();
  assert.equal(before.envelopes.length,1);
  await assert.rejects(captureLoopbackRelayObservation({endpoint:relay.url,
   canonicalAddress:bob.canonicalAddress,deviceId:bob.rootDeviceId,authToken:'z'.repeat(60),
   relayId:relay.relayId}),/refused/);
  await relay.close();relay=await startRelayServer({host:'127.0.0.1',port:0,dataDir:folder});
  const after=await observed();
  const source=historical(),candidate=structuredClone(source);
  const result=reconcileRelayObservationLab(before,after,source,candidate);
  assert.equal(result.observedRelayWindowStable,true);
  assert.equal(result.historicalCollectionsMatch,true);
  assert.equal(result.pendingIncomingVisible,1);
  assert.equal(result.remoteQueueReconciled,false);
  assert.equal(result.legacyDeletionAuthorized,false);
  assert.equal(result.queuedOutboundPreserved,true);
  assert.equal(result.historicalPrekeysPreserved,true);
  // The receipt journal retains only bounded flags and digests, never the
  // relay token, historical message body, or incoming ciphertext.
  const journalFiles=new Map();
  const auditStore={
   async probe(name){return journalFiles.has(name)?'present':'absent';},
   async read(name){return Buffer.from(journalFiles.get(name));},
   async write(name,bytes){assert.equal(journalFiles.has(name),false);journalFiles.set(name,Buffer.from(bytes));}
  };
  const auditKey=randomBytes(32),auditScope={rootPin:'f'.repeat(64),transactionId:'e'.repeat(32)};
  const reportFacts={relayIdSha256:createHash('sha256').update(relay.relayId).digest('hex'),
   observedWindowSha256:createHash('sha256').update(JSON.stringify([result.envelopes,result.receipts])).digest('hex'),
   observedRelayWindowStable:result.observedRelayWindowStable,
   observedRelayWindowNotAtCap:result.observedRelayWindowNotAtCap,
   pendingIncomingVisible:result.pendingIncomingVisible,
   pendingReceiptsVisible:result.pendingReceiptsVisible};
  await appendMigrationAuditLabRecord(auditStore,auditKey,auditScope,{sequence:0,phase:'prepared',
   facts:{sourceManifestSha256:'1'.repeat(64),candidateManifestSha256:'2'.repeat(64)}});
  await appendMigrationAuditLabRecord(auditStore,auditKey,auditScope,{sequence:1,phase:'snapshot-verified',
   facts:{historicalCollectionsMatch:true,outboxPreserved:true,prekeysPreserved:true}});
  const receipt=await appendMigrationAuditLabRecord(auditStore,auditKey,auditScope,{
   sequence:2,phase:'relay-observed',facts:reportFacts});
  assert.equal(receipt.created,true);assert.equal(receipt.liveRestoreAuthorized,false);
  assert.equal(journalFiles.size,3);
  assert.equal([...journalFiles.values()].some(buf=>buf.includes(Buffer.from(bob.token))),false);
  auditKey.fill(0);
  // The audit never acknowledges or consumes the real relay test envelope.
  assert.equal((await observed()).envelopes.length,1);
  await send('client-message-0002');
  const drift=reconcileRelayObservationLab(before,await observed(),source,structuredClone(source));
  assert.equal(drift.observedRelayWindowStable,false);
  assert.equal(drift.envelopes.added,1);
  assert.equal(drift.liveRestoreAuthorized,false);
 }finally{if(relay)await relay.close();await rm(folder,{recursive:true,force:true});}
});
test('window saturation, tampering, forged identity and claimed-prekey replay cannot prove completeness',()=>{
 const ctx={labOnly:true,relayId:'1'.repeat(64),
  canonicalAddress:'audit-bob~'+'a'.repeat(32)+'@quantic',deviceId:'d-'+'b'.repeat(32)};
 const makeEntry=i=>({id:'e'+i,clientMessageId:'client-message-'+String(i).padStart(5,'0'),
  to:ctx.canonicalAddress,toDeviceId:ctx.deviceId,
  from:'audit-alice~'+'c'.repeat(32)+'@quantic',fromDeviceId:'d-'+'d'.repeat(32),
  ciphertext:'opaque',iv:'synthetic',ephemeralPublicKey:{kty:'EC',crv:'P-256',x:'x',y:'y'}});
 const obs=()=>({...ctx,envelopes:[makeEntry(1)],receipts:[]});
 const old=historical(),copy=structuredClone(old);
 const stable=reconcileRelayObservationLab(obs(),obs(),old,copy);
 assert.equal(stable.observedRelayWindowStable,true);
 assert.equal(stable.remoteQueueReconciled,false);
 const cap={...ctx,envelopes:Array.from({length:100},(_,i)=>makeEntry(i)),receipts:[]};
 const limited=reconcileRelayObservationLab(cap,structuredClone(cap),old,structuredClone(old));
 assert.equal(limited.observedRelayWindowNotAtCap,false);
 const tampered=obs();tampered.envelopes[0].ciphertext='changed';
 assert.equal(reconcileRelayObservationLab(obs(),tampered,old,structuredClone(old)).envelopes.modified,1);
 const replay=structuredClone(old);replay.prekeys[0].state='unused';
 assert.equal(reconcileRelayObservationLab(obs(),obs(),old,replay).historicalPrekeysPreserved,false);
 const invalid=obs();invalid.deviceId='d-'+'e'.repeat(32);
 assert.throws(()=>reconcileRelayObservationLab(obs(),invalid,old,structuredClone(old)),/refused/);
 const duplicates=obs();duplicates.envelopes.push({...duplicates.envelopes[0]});
 assert.throws(()=>reconcileRelayObservationLab(obs(),duplicates,old,structuredClone(old)),/refused/);
});
