import test from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import {openMultiplexSender,openMultiplexReceiver,MUX_POLICY} from '../lib/quantic/scattering-multiplex-lab.mjs';
import {sealReliable,openReliable} from '../labs/quantic-native/scattering/scattering-reliable-lab.mjs';
const config=()=>({members:Array.from({length:32},(_,i)=>({id:'demo-'+i,secret:randomBytes(32)})),epoch:randomBytes(32),direction:'a-b'});
test('32 users share a fixed outer stream; independent inner keys and round-robin delivery',t=>{
 const c=config(),s=openMultiplexSender(c),r=openMultiplexReceiver(c),outerKey=randomBytes(32),expected=new Map();
 try{
  for(const m of c.members)for(let i=0;i<10;i++){const b=randomBytes(MUX_POLICY.payload);s.enqueue(m.id,b);if(!expected.has(m.id))expected.set(m.id,[]);expected.get(m.id).push(b);}
  let delivered=0;const firstRound=[];
  for(let seq=0;seq<1000;seq++){
   const inner=s.nextSlot();assert.equal(inner.length,128);
   const outer=sealReliable(outerKey,{seq,ack:0,data:inner});assert.equal(outer.length,168);
   const result=r.receive(openReliable(outerKey,outer).data);
   if(result){assert.deepEqual(result.data,expected.get(result.member).shift());delivered++;if(delivered<=32)firstRound.push(result.member);}
  }
  assert.deepEqual(firstRound,c.members.map(m=>m.id));assert.equal(delivered,320);assert.ok([...expected.values()].every(q=>q.length===0));
  assert.deepEqual(s.stats(),{queued:0,slots:1000});
  t.diagnostic('MUX_LAB_V1 '+JSON.stringify({members:32,slots:1000,delivered,decoys:680,applicationBytes:delivered*MUX_POLICY.payload,outerBytes:168000,payloadPerUsefulCell:MUX_POLICY.payload}));
 }finally{s.close();r.close();outerKey.fill(0);}
});
test('wrong epoch or direction, forged routing label, ciphertext tampering and replay never deliver',()=>{
 const c=config(),s=openMultiplexSender(c),r=openMultiplexReceiver(c),wrong=openMultiplexReceiver({...c,epoch:randomBytes(32)}),reverse=openMultiplexReceiver({...c,direction:'b-a'}),outsider=openMultiplexReceiver({...c,members:[{id:'demo-0',secret:randomBytes(32)},c.members[1]]});
 try{
  const b=randomBytes(78);s.enqueue('demo-0',b);const a=s.nextSlot();
  assert.equal(wrong.receive(a),null);assert.equal(reverse.receive(a),null);assert.equal(outsider.receive(a),null);
  for(const offset of [0,20,40,127]){const bad=Buffer.from(a);bad[offset]^=1;assert.equal(r.receive(bad),null);}
  assert.deepEqual(r.receive(a),{member:'demo-0',data:b});assert.equal(r.receive(a),null);
  assert.throws(()=>r.receive(a.subarray(0,127)));
  assert.throws(()=>s.enqueue('demo-0',Buffer.alloc(79)));
  assert.throws(()=>s.enqueue('demo-unknown',b));
  for(let i=0;i<32;i++)s.enqueue('demo-0',b);
  assert.throws(()=>s.enqueue('demo-0',b));s.enqueue('demo-1',b);
  assert.equal(r.receive(s.nextSlot()).member,'demo-1');
  assert.throws(()=>openMultiplexSender({...c,members:[c.members[0],{...c.members[1],secret:c.members[0].secret}]}));
 }finally{for(const o of [s,r,wrong,reverse,outsider])o.close();}
 assert.throws(()=>s.nextSlot());
});
test('saturation cannot add slots; global queue stays bounded and all slots remain fixed-size',()=>{
 const c=config(),s=openMultiplexSender(c),idle=openMultiplexSender(c),r=openMultiplexReceiver(c);
 try{
  for(let k=0;k<512;k++)s.enqueue('demo-'+(k%16),Buffer.alloc(78,1));
  assert.throws(()=>s.enqueue('demo-16',Buffer.alloc(78,1)));
  let delivered=0;
  for(let i=0;i<512;i++){const busy=s.nextSlot(),empty=idle.nextSlot();assert.equal(busy.length,empty.length);if(r.receive(busy))delivered++;}
  assert.equal(delivered,512);assert.deepEqual(s.stats(),idle.stats());
 }finally{s.close();idle.close();r.close();}
});
