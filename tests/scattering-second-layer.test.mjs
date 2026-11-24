import test from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import {sealLayeredLab,peelSecondLayer,peelAndResealLab,SECOND_LAYER_BYTES} from '../lib/quantic/scattering-second-layer-lab.mjs';
import {resealLabHop} from '../lib/quantic/scattering-hop-reseal-lab.mjs';
import {openNestedLab,openEndToEndLab} from '../lib/quantic/scattering-e2e-envelope-lab.mjs';
import {openReliable,sealReliable} from '../labs/quantic-native/scattering/scattering-reliable-lab.mjs';
test('second relay layer changes visible payload, without giving relay one endpoint ciphertext',()=>{
 const keys=Array.from({length:5},()=>randomBytes(32)),[a,mid,out,second,e2e]=keys;
 try{
  for(let seq=0;seq<16;seq++){
   const data=randomBytes(59);
   const p=sealLayeredLab({hopKey:a,secondKey:second,endToEndKey:e2e,senderId:0,seq,data});
   const q=resealLabHop({inputKey:a,outputKey:mid,packet:p,hopSeq:seq});
   const r=peelAndResealLab({inputKey:mid,secondKey:second,outputKey:out,packet:q,hopSeq:seq});
   assert.ok([p,q,r].every(x=>x.length===168));
   const before=openReliable(a,p).data,after=openReliable(out,r).data;
   assert.equal(before.length,SECOND_LAYER_BYTES);
   assert.equal(after.length,92);
   assert.equal(before.includes(after),false);
   assert.equal(peelSecondLayer(a,before),null);
   assert.equal(peelSecondLayer(mid,before),null);
   assert.equal(openEndToEndLab(a,after),null);
   assert.deepEqual(openNestedLab({hopKey:out,endToEndKey:e2e,packet:r}),{senderId:0,seq,data});
   // Negative control: cooperating relays CAN still reconstruct this mapping.
   assert.deepEqual(peelSecondLayer(second,before),after);
  }
 }finally{for(const k of keys)k.fill(0);}
});
test('authenticated hop wrapper cannot make a corrupted second layer valid',()=>{
 const keys=Array.from({length:4},()=>randomBytes(32)),[a,out,second,e2e]=keys;
 try{
  const p=sealLayeredLab({hopKey:a,secondKey:second,endToEndKey:e2e,senderId:0,seq:0,data:randomBytes(59)});
  const b=Buffer.from(openReliable(a,p).data);b[45]^=1;
  const forged=sealReliable(a,{seq:0,ack:0,data:b});
  assert.equal(peelAndResealLab({inputKey:a,secondKey:second,outputKey:out,packet:forged,hopSeq:0}),null);
  assert.equal(peelSecondLayer(second,b.subarray(0,119)),null);
  assert.throws(()=>sealLayeredLab({hopKey:a,secondKey:a,endToEndKey:e2e,senderId:0,seq:0,data:randomBytes(59)}));
 }finally{for(const k of keys)k.fill(0);}
});
