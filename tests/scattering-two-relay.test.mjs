import test from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import {sealNestedLab,openNestedLab,openEndToEndLab} from '../lib/quantic/scattering-e2e-envelope-lab.mjs';
import {resealLabHop} from '../lib/quantic/scattering-hop-reseal-lab.mjs';
import {openReliable} from '../labs/quantic-native/scattering/scattering-reliable-lab.mjs';
import {createScatteringBatchMixer} from '../lib/quantic/scattering-batch-mixer-lab.mjs';

test('two sequential independent hop reseals preserve endpoint authentication and change outer bytes',()=>{
 const keys=Array.from({length:4},()=>randomBytes(32)),[a,mid,out,e2e]=keys;
 try{
  for(let seq=0;seq<16;seq++){
   const data=randomBytes(59);
   const first=sealNestedLab({hopKey:a,endToEndKey:e2e,senderId:0,seq,data});
   const second=resealLabHop({inputKey:a,outputKey:mid,packet:first,hopSeq:seq});
   const third=resealLabHop({inputKey:mid,outputKey:out,packet:second,hopSeq:seq});
   assert.equal(new Set([first,second,third].map(x=>x.toString('hex'))).size,3);
   assert.deepEqual(openNestedLab({hopKey:out,endToEndKey:e2e,packet:third}),{senderId:0,seq,data});
   assert.equal(openReliable(a,second),null);
   assert.equal(openReliable(mid,third),null);
   // Explicit limitation: two colluding relays may compare the inner blob.
   const inner1=openReliable(a,first).data,inner2=openReliable(mid,second).data;
   assert.deepEqual(inner1,inner2);
   for(const k of [a,mid,out])assert.equal(openEndToEndLab(k,inner1),null);
  }
 }finally{for(const k of keys)k.fill(0);}
});
test('second independent mix does not drop or repeat authentic nested messages',()=>{
 const keys=Array.from({length:4},()=>randomBytes(32)),[a,mid,out,e2e]=keys;
 const messages=[],final=[];let i=0,j=0;
 try{
  const second=createScatteringBatchMixer({batchSize:8,draw:()=>0,onBatch(batch){
   for(const x of batch)final.push(resealLabHop({inputKey:mid,outputKey:out,packet:x.packet,hopSeq:j++}));
  }});
  const first=createScatteringBatchMixer({batchSize:8,draw:()=>0,onBatch(batch){
   for(const x of batch)second.add({source:0,packet:resealLabHop({inputKey:a,outputKey:mid,packet:x.packet,hopSeq:i++})});
  }});
  for(let seq=0;seq<24;seq++){
   const data=randomBytes(59);messages.push(data);
   first.add({source:seq%2,packet:sealNestedLab({hopKey:a,endToEndKey:e2e,senderId:seq%2,seq,data})});
  }
  assert.equal(final.length,24);const seen=new Set();
  for(const packet of final){
   const msg=openNestedLab({hopKey:out,endToEndKey:e2e,packet});
   assert.ok(msg&&!seen.has(msg.seq));seen.add(msg.seq);
   assert.deepEqual(msg.data,messages[msg.seq]);assert.equal(msg.senderId,msg.seq%2);
  }
  assert.equal(seen.size,24);
 }finally{for(const k of keys)k.fill(0);}
});
