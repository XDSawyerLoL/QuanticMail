import test from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import dgram from 'node:dgram';
import {
 FRAME_BYTES, MAX_MESSAGE_BYTES, deriveSessionKey, FrameSender, FrameReceiver,
 ReplayWindow, fragmentMessage, MessageCollector, stratifiedSlots
} from '../src/transport.mjs';
import {verifyAllEightShardSubsets, DATA_SHARDS, SHARD_SIZE} from '../src/fec.mjs';
import {scheduleKey, dataPositions, emitWindow} from '../src/scheduler.mjs';
import {runBenchmark} from '../src/benchmark.mjs';

const master=Buffer.alloc(32,0x53),session=Buffer.alloc(16,0x91);
function pair(){return [new FrameSender({masterSecret:master,sessionId:session}),new FrameReceiver({masterSecret:master,sessionId:session})];}

test('fresh session derivation and domain separation',()=>{
 assert.equal(deriveSessionKey(master,session).length,32);
 assert.notDeepEqual(deriveSessionKey(master,session),deriveSessionKey(master,Buffer.alloc(16,2)));
 assert.throws(()=>deriveSessionKey(master,Buffer.alloc(15)));
});
test('fixed packet size, encrypted cover and data header',()=>{
 const [s,r]=pair(),id=randomBytes(8);
 const c=s.nextCover(),d=s.nextShard({messageId:id,index:0,data:Buffer.alloc(SHARD_SIZE,0x41)});
 assert.equal(c.length,FRAME_BYTES);assert.equal(d.length,FRAME_BYTES);
 assert.notDeepEqual(c,d);
 assert.equal(r.accept(c).kind,'cover');
 const a=r.accept(d);assert.equal(a.kind,'data');assert.deepEqual(a.shard.data,Buffer.alloc(SHARD_SIZE,0x41));
});
test('authentication rejects tampering, wrong key and session',()=>{
 const [s,r]=pair(),p=s.nextCover();
 assert.equal(r.accept(Buffer.alloc(167)).error,'invalid_frame_size');
 const changed=Buffer.from(p);changed[32]^=0x80;
 assert.equal(r.accept(changed).error,'authentication_failed');
 assert.equal(new FrameReceiver({masterSecret:Buffer.alloc(32,9),sessionId:session}).accept(p).ok,false);
 assert.equal(new FrameReceiver({masterSecret:master,sessionId:Buffer.alloc(16,9)}).accept(p).ok,false);
 assert.equal(r.accept(p).ok,true); // Failed authentication did not poison replay state
});
test('anti replay, out-of-order and bounded stale window',()=>{
 const [s,r]=pair(),a=Array.from({length:40},()=>s.nextCover());
 assert.equal(r.accept(a[9]).ok,true);
 assert.equal(r.accept(a[9]).error,'replayed_or_stale');
 assert.equal(r.accept(a[8]).ok,true);
 assert.equal(r.accept(a[14]).ok,true);
 assert.equal(r.accept(a[10]).ok,true);
 const gate=new ReplayWindow(16);
 assert.equal(gate.accept(1n),true);assert.equal(gate.accept(20n),true);
 assert.equal(gate.accept(1n),false);assert.equal(gate.accept(19n),true);assert.equal(gate.accept(19n),false);
 assert.equal(gate.accept(2n**63n),true);
});
test('reject invalid shard profile and oversized messages',()=>{
 const [s]=pair();const mid=randomBytes(8);
 assert.throws(()=>s.nextShard({messageId:mid,index:16,data:Buffer.alloc(118)}));
 assert.throws(()=>s.nextShard({messageId:mid,index:0,data:Buffer.alloc(117)}));
 assert.throws(()=>fragmentMessage(Buffer.alloc(MAX_MESSAGE_BYTES+1)));
 assert.equal(fragmentMessage(Buffer.alloc(MAX_MESSAGE_BYTES)).length,16);
});
test('real 8-of-16 Reed Solomon reconstruction',()=>{
 const message=Buffer.from('a v14 secure message with 8/16 erasure recovery');
 const fragments=fragmentMessage(message),collector=new MessageCollector();
 const subset=[0,1,3,5,8,10,12,15];
 let delivered=null;
 for(const i of subset)delivered=collector.add(fragments[i])??delivered;
 assert.ok(delivered);assert.deepEqual(delivered.message,message);
 // Other eight shards of the same message may not trigger a second delivery.
 for(let i=0;i<16;i++)assert.equal(collector.add(fragments[i]),null);
});
test('all C(16,8) erasure subsets are invertible',()=>{
 const r=verifyAllEightShardSubsets();assert.equal(r.pass,true);assert.equal(r.checked,12870);assert.equal(r.failures,0);
});
test('keyed slot schedule avoids duplicates and activity-dependent change',()=>{
 const k=scheduleKey(master,session);
 for(const mode of ['keyed_stratified','public_stratified','keyed_uniform','keyed_antipodal']){
  for(let w=0;w<100;w++){
   const a=dataPositions(k,w,{mode}),b=dataPositions(k,w,{mode});
   assert.deepEqual(a,b);assert.equal(new Set(a).size,16);
   assert.ok(a.every(x=>x>=0&&x<28));
  }
 }
 assert.notDeepEqual(dataPositions(k,0),dataPositions(k,1));
 assert.deepEqual(stratifiedSlots(),dataPositions(k,0,{mode:'public_stratified'}));
});
test('antipodal schedule survives every contiguous half-window loss, even cyclic',()=>{
 const k=scheduleKey(master,session);
 for(let w=0;w<256;w++){
  const positions=dataPositions(k,w,{mode:'keyed_antipodal'});
  for(let start=0;start<28;start++){
   const dropped=new Set(Array.from({length:14},(_,i)=>(start+i)%28));
   assert.equal(positions.filter(x=>!dropped.has(x)).length,8);
  }
 }
});
test('revealed schedule key defeats any claimed universal recovery guarantee',()=>{
 const k=scheduleKey(master,session),positions=dataPositions(k,777,{mode:'keyed_antipodal'});
 // An adversary who knows the secret schedule can drop 9 actual shard slots.
 const target=new Set(positions.slice(0,9));
 assert.equal(positions.filter(x=>!target.has(x)).length,7);
});
test('receiver restart with reused session is NOT replay safe (known limitation)',()=>{
 const [s,r]=pair(),frame=s.nextCover();
 assert.equal(r.accept(frame).ok,true);
 assert.equal(new FrameReceiver({masterSecret:master,sessionId:session}).accept(frame).ok,true);
});
test('outer frame count and length same with/without user message',()=>{
 const sk=scheduleKey(master,session),frags=fragmentMessage(Buffer.from('secret'));
 const [s0]=pair(),[s1]=pair();
 const h0=emitWindow(s0,sk,0,{shards:null}),h1=emitWindow(s1,sk,0,{shards:frags});
 assert.equal(h0.frames.length,28);assert.equal(h1.frames.length,28);
 assert.deepEqual(h0.frames.map(x=>x.length),h1.frames.map(x=>x.length));
 assert.deepEqual(h0.placement,h1.placement);
 const receiver=new FrameReceiver({masterSecret:master,sessionId:session});
 const reconstructed=new MessageCollector();let msg=null;
 for(const frame of h1.frames){const out=receiver.accept(frame);if(out.shard)msg=reconstructed.add(out.shard)?.message??msg;}
 assert.deepEqual(msg,Buffer.from('secret'));
});
test('balanced adversary simulations are deterministic and remain bounded',()=>{
 const a=runBenchmark({trials:300,seed:'v14-test'}),b=runBenchmark({trials:300,seed:'v14-test'});
 assert.deepEqual(a,b);
 for(const rates of Object.values(a.attacks))for(const v of Object.values(rates))assert.ok(v.rate>=0&&v.rate<=1);
 assert.equal(a.attacks.public_target9.public_stratified.rate,0);
});
test('UDP loopback receiver independently decrypts and reassembles',async()=>{
 const socket=dgram.createSocket('udp4');
 await new Promise(resolve=>socket.bind(0,'127.0.0.1',resolve));
 const port=socket.address().port,tx=dgram.createSocket('udp4');
 const sk=scheduleKey(master,session),[sender,receiver]=pair(),collector=new MessageCollector();
 const message=Buffer.from('loopback verification with application-level authentication');
 const {frames,placement}=emitWindow(sender,sk,1,{shards:fragmentMessage(message)});
 const dropped=new Set(placement.slice(0,5));let count=0,delivered=null;
 const seen=new Promise((resolve,reject)=>{
  const timer=setTimeout(()=>reject(new Error(`timeout after ${count} received`)),5000);
  socket.on('message',p=>{
   count++;const out=receiver.accept(p);
   assert.equal(out.ok,true);
   if(out.shard)delivered=collector.add(out.shard)?.message??delivered;
   if(count===frames.length-dropped.size){clearTimeout(timer);resolve();}
  });
 });
 try{
  for(let i=0;i<frames.length;i++)if(!dropped.has(i))await new Promise((resolve,reject)=>tx.send(frames[i],port,'127.0.0.1',e=>e?reject(e):resolve()));
  await seen;assert.deepEqual(delivered,message);
 }finally{tx.close();socket.close();}
});
