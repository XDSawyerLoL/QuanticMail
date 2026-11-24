import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,randomBytes} from 'node:crypto';
import {mkdtemp,readFile,writeFile,unlink,rm,copyFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {FrameSender,FrameReceiver,fragmentMessage,MessageCollector} from '../src/transport.mjs';
import {
 initiateSession,respondSession,finishInitiatorSession,finishResponderSession,publicSigningKeyFingerprint
} from '../src/session-v15.mjs';
import {DurableFrameReceiver} from '../src/durable-replay-v15.mjs';

const identities=()=>({alice:generateKeyPairSync('ed25519'),bob:generateKeyPairSync('ed25519'),eve:generateKeyPairSync('ed25519')});
function complete(keys=identities()){
 const {handle:i,hello}=initiateSession({localSigningPrivateKey:keys.alice.privateKey,peerSigningPublicKey:keys.bob.publicKey});
 const {handle:r,response}=respondSession({localSigningPrivateKey:keys.bob.privateKey,peerSigningPublicKey:keys.alice.publicKey,hello});
 const {session:initiator,finish}=finishInitiatorSession(i,response);
 const responder=finishResponderSession(r,finish);
 return {initiator,responder,keys,hello,response,finish};
}
const tempfile=async()=>{const dir=await mkdtemp(join(tmpdir(),'qs-v15-'));return {dir,file:join(dir,'replay.state')};};

test('V15 pinned Ed25519 identities and fresh ephemeral X25519 establish directional secrets',()=>{
 const {initiator:a,responder:b,keys}=complete();
 assert.deepEqual(a.sessionId,b.sessionId);
 assert.deepEqual(a.sendMasterSecret,b.receiveMasterSecret);
 assert.deepEqual(a.receiveMasterSecret,b.sendMasterSecret);
 assert.notDeepEqual(a.sendMasterSecret,a.receiveMasterSecret);
 assert.equal(a.postQuantum,false);
 assert.equal(a.identitySignature,'Ed25519');
 assert.equal(publicSigningKeyFingerprint(keys.alice.publicKey).length,64);
});
test('V15 actual encrypted frames are accepted only in their direction',()=>{
 const {initiator:a,responder:b}=complete();
 const tx=new FrameSender({masterSecret:a.sendMasterSecret,sessionId:a.sessionId});
 const rx=new FrameReceiver({masterSecret:b.receiveMasterSecret,sessionId:b.sessionId});
 const reverse=new FrameReceiver({masterSecret:a.receiveMasterSecret,sessionId:a.sessionId});
 const packets=[tx.nextCover(),tx.nextCover()];
 assert.equal(rx.accept(packets[0]).ok,true);
 assert.equal(rx.accept(packets[1]).ok,true);
 assert.equal(reverse.accept(packets[0]).ok,false);
});
test('V15 old session packets cannot be replayed into a new handshake',()=>{
 const keys=identities(),a=complete(keys),b=complete(keys);
 assert.notDeepEqual(a.initiator.sessionId,b.initiator.sessionId);
 const oldFrame=new FrameSender({masterSecret:a.initiator.sendMasterSecret,sessionId:a.initiator.sessionId}).nextCover();
 const newReceiver=new FrameReceiver({masterSecret:b.responder.receiveMasterSecret,sessionId:b.responder.sessionId});
 assert.equal(newReceiver.accept(oldFrame).error,'authentication_failed');
});
test('V15 invalid or substituted identity rejects opening hello',()=>{
 const keys=identities(),{hello}=initiateSession({localSigningPrivateKey:keys.alice.privateKey,peerSigningPublicKey:keys.bob.publicKey});
 assert.throws(()=>respondSession({localSigningPrivateKey:keys.bob.privateKey,peerSigningPublicKey:keys.eve.publicKey,hello}),/not authenticated/);
 const fake={...hello,nonce:Buffer.from(hello.nonce)};fake.nonce[0]^=1;
 assert.throws(()=>respondSession({localSigningPrivateKey:keys.bob.privateKey,peerSigningPublicKey:keys.alice.publicKey,hello:fake}),/not authenticated/);
});
test('V15 tampered responder signature and wrong pinned identity are rejected',()=>{
 const keys=identities(),{handle,hello}=initiateSession({localSigningPrivateKey:keys.alice.privateKey,peerSigningPublicKey:keys.bob.publicKey});
 const {response}=respondSession({localSigningPrivateKey:keys.eve.privateKey,peerSigningPublicKey:keys.alice.publicKey,hello});
 assert.throws(()=>finishInitiatorSession(handle,response),/not authenticated/);
});
test('V15 finish MAC binds the shared ephemeral key and rejects tampering',()=>{
 const keys=identities(),{handle:i,hello}=initiateSession({localSigningPrivateKey:keys.alice.privateKey,peerSigningPublicKey:keys.bob.publicKey});
 const {handle:r,response}=respondSession({localSigningPrivateKey:keys.bob.privateKey,peerSigningPublicKey:keys.alice.publicKey,hello});
 const {finish}=finishInitiatorSession(i,response);
 const tampered={confirmation:Buffer.from(finish.confirmation)};tampered.confirmation[2]^=1;
 assert.throws(()=>finishResponderSession(r,tampered),/confirmation/);
 assert.throws(()=>finishResponderSession(r,finish),/already used/);
 assert.throws(()=>finishInitiatorSession(i,response),/already used/);
});
test('V15 malformed handshake peer key is rejected without receiving traffic',()=>{
 const keys=identities(),{hello}=initiateSession({localSigningPrivateKey:keys.alice.privateKey,peerSigningPublicKey:keys.bob.publicKey});
 assert.throws(()=>respondSession({localSigningPrivateKey:keys.bob.privateKey,peerSigningPublicKey:keys.alice.publicKey,hello:{...hello,ephemeralPublicKey:randomBytes(44)}}));
});
test('V15 durable replay rejects duplicates across clean process restart',async()=>{
 const {initiator:a,responder:b}=complete(),{dir,file}=await tempfile();
 try{
  const tx=new FrameSender({masterSecret:a.sendMasterSecret,sessionId:a.sessionId});
  const packets=Array.from({length:5},()=>tx.nextCover());
  const config={masterSecret:b.receiveMasterSecret,sessionId:b.sessionId,stateFile:file,replayWindow:32};
  let rx=await DurableFrameReceiver.create(config);
  assert.equal((await rx.accept(packets[3])).ok,true);
  assert.equal((await rx.accept(packets[1])).ok,true);
  await rx.close();
  rx=await DurableFrameReceiver.resume(config);
  assert.equal((await rx.accept(packets[3])).error,'replayed_or_stale');
  assert.equal((await rx.accept(packets[1])).error,'replayed_or_stale');
  assert.equal((await rx.accept(packets[2])).ok,true);
  await rx.close();
 }finally{await rm(dir,{recursive:true,force:true});}
});
test('V15 replay state tamper is fail closed, not reset to fresh window',async()=>{
 const {responder:b}=complete(),{dir,file}=await tempfile();
 try{
  const cfg={masterSecret:b.receiveMasterSecret,sessionId:b.sessionId,stateFile:file};
  const rx=await DurableFrameReceiver.create(cfg);await rx.close();
  const state=JSON.parse(await readFile(file,'utf8'));state.bits='f';
  await writeFile(file,JSON.stringify(state));
  await assert.rejects(()=>DurableFrameReceiver.resume(cfg),/authentication/);
  await assert.rejects(()=>DurableFrameReceiver.create(cfg),/EEXIST/);
 }finally{await rm(dir,{recursive:true,force:true});}
});
test('V15 receiver cannot start while same replay file is opened elsewhere',async()=>{
 const {responder:b}=complete(),{dir,file}=await tempfile();
 try{
  const cfg={masterSecret:b.receiveMasterSecret,sessionId:b.sessionId,stateFile:file};
  const rx=await DurableFrameReceiver.create(cfg);
  await assert.rejects(()=>DurableFrameReceiver.resume(cfg),/EEXIST/);
  await rx.close();
  const resumed=await DurableFrameReceiver.resume(cfg);await resumed.close();
 }finally{await rm(dir,{recursive:true,force:true});}
});
test('V15 simultaneous replay admissions are serialized: only first survives',async()=>{
 const {initiator:a,responder:b}=complete(),{dir,file}=await tempfile();
 try{
  const rx=await DurableFrameReceiver.create({masterSecret:b.receiveMasterSecret,sessionId:b.sessionId,stateFile:file});
  const packet=new FrameSender({masterSecret:a.sendMasterSecret,sessionId:a.sessionId}).nextCover();
  const both=await Promise.all([rx.accept(packet),rx.accept(packet)]);
  assert.equal(both.filter(v=>v.ok).length,1);
  assert.equal(both.filter(v=>v.error==='replayed_or_stale').length,1);
  await rx.close();
 }finally{await rm(dir,{recursive:true,force:true});}
});
test('V15 state loss is fail closed: resume never silently initializes missing state',async()=>{
 const {responder:b}=complete(),{dir,file}=await tempfile();
 try{
  const cfg={masterSecret:b.receiveMasterSecret,sessionId:b.sessionId,stateFile:file};
  await assert.rejects(()=>DurableFrameReceiver.resume(cfg),/ENOENT/);
  const rx=await DurableFrameReceiver.create(cfg);await rx.close();
  await unlink(file);
  await assert.rejects(()=>DurableFrameReceiver.resume(cfg),/ENOENT/);
 }finally{await rm(dir,{recursive:true,force:true});}
});
test('V15 session key and replay state are bound to selected peer',async()=>{
 const x=complete(),y=complete(),{dir,file}=await tempfile();
 try{
  const cfg={masterSecret:x.responder.receiveMasterSecret,sessionId:x.responder.sessionId,stateFile:file};
  const rx=await DurableFrameReceiver.create(cfg);await rx.close();
  await assert.rejects(()=>DurableFrameReceiver.resume({masterSecret:y.responder.receiveMasterSecret,sessionId:y.responder.sessionId,stateFile:file}),/authentication|mismatch/);
 }finally{await rm(dir,{recursive:true,force:true});}
});
test('V15 real shards with authenticated handshake and persisted replay',async()=>{
 const {initiator:a,responder:b}=complete(),{dir,file}=await tempfile();
 try{
  const sent=new FrameSender({masterSecret:a.sendMasterSecret,sessionId:a.sessionId}),msg=Buffer.from('This delivery crossed an authenticated laboratory session');
  const parts=fragmentMessage(msg),frames=parts.slice(0,8).map(p=>sent.nextShard(p));
  const rx=await DurableFrameReceiver.create({masterSecret:b.receiveMasterSecret,sessionId:b.sessionId,stateFile:file});
  const collector=new MessageCollector();let delivered=null;
  for(const f of frames){const result=await rx.accept(f);assert.equal(result.ok,true);delivered=collector.add(result.shard)?.message??delivered;}
  assert.deepEqual(delivered,msg);
  await rx.close();
  const resumed=await DurableFrameReceiver.resume({masterSecret:b.receiveMasterSecret,sessionId:b.sessionId,stateFile:file});
  for(const f of frames)assert.equal((await resumed.accept(f)).error,'replayed_or_stale');
  await resumed.close();
 }finally{await rm(dir,{recursive:true,force:true});}
});

test('V15 replay protection survives an actual second Node process',async()=>{
 const {spawnSync}=await import('node:child_process');
 const {initiator:a,responder:b}=complete(),{dir,file}=await tempfile();
 try{
  const cfg={masterSecret:b.receiveMasterSecret,sessionId:b.sessionId,stateFile:file};
  const tx=new FrameSender({masterSecret:a.sendMasterSecret,sessionId:a.sessionId});
  const packet=tx.nextCover();
  const rx=await DurableFrameReceiver.create(cfg);
  assert.equal((await rx.accept(packet)).ok,true);await rx.close();
  const moduleUri=new URL('../src/durable-replay-v15.mjs',import.meta.url).href;
  const code=`import {DurableFrameReceiver} from ${JSON.stringify(moduleUri)};
    const [state,key,id,pkt]=process.argv.slice(1);
    const receiver=await DurableFrameReceiver.resume({stateFile:state,masterSecret:Buffer.from(key,'hex'),sessionId:Buffer.from(id,'hex')});
    const result=await receiver.accept(Buffer.from(pkt,'base64'));
    await receiver.close();
    if(result.error!=='replayed_or_stale')process.exit(5);
    process.stdout.write(result.error);`;
  const child=spawnSync(process.execPath,['--input-type=module','-e',code,file,b.receiveMasterSecret.toString('hex'),b.sessionId.toString('hex'),packet.toString('base64')],{encoding:'utf8',timeout:4000});
  assert.equal(child.status,0,child.stderr);
  assert.equal(child.stdout,'replayed_or_stale');
 }finally{await rm(dir,{recursive:true,force:true});}
});

test('V15 storage commit failure causes immediate fail-closed behavior',async()=>{
 const {initiator:a,responder:b}=complete(),{dir,file}=await tempfile();
 try{
  const rx=await DurableFrameReceiver.create({masterSecret:b.receiveMasterSecret,sessionId:b.sessionId,stateFile:file});
  const pkt=new FrameSender({masterSecret:a.sendMasterSecret,sessionId:a.sessionId}).nextCover();
  rx.stateFile=join(dir,'missing-subdirectory','state.json'); // lab fault injection: unwriteable destination
  assert.equal((await rx.accept(pkt)).error,'durable_commit_failed');
  assert.equal((await rx.accept(pkt)).error,'receiver_closed_or_fail_closed');
  await rx.close();
 }finally{await rm(dir,{recursive:true,force:true});}
});

test('V15 documented limitation: restored authentic older snapshot permits replay',async()=>{
 const {initiator:a,responder:b}=complete(),{dir,file}=await tempfile();
 try{
  const tx=new FrameSender({masterSecret:a.sendMasterSecret,sessionId:a.sessionId});
  const [first,second]=[tx.nextCover(),tx.nextCover()];
  const cfg={masterSecret:b.receiveMasterSecret,sessionId:b.sessionId,stateFile:file};
  const rx=await DurableFrameReceiver.create(cfg);
  assert.equal((await rx.accept(first)).ok,true);
  const oldSnapshot=await readFile(file);
  assert.equal((await rx.accept(second)).ok,true);
  await rx.close();
  await writeFile(file,oldSnapshot); // attacker-controlled rollback to a valid prior authenticated snapshot
  const restarted=await DurableFrameReceiver.resume(cfg);
  assert.equal((await restarted.accept(second)).ok,true); // limitation, NOT a desired security guarantee
  await restarted.close();
 }finally{await rm(dir,{recursive:true,force:true});}
});