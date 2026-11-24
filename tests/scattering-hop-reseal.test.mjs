import test from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import {sealReliable,openReliable} from '../labs/quantic-native/scattering/scattering-reliable-lab.mjs';
import {resealLabHop} from '../lib/quantic/scattering-hop-reseal-lab.mjs';
test('trusted lab hop transforms each incoming 168-byte cell with independent key',()=>{
 const a=randomBytes(32),b=randomBytes(32),outKey=randomBytes(32);
 const decoded=[];
 for(const [id,key] of [[0,a],[1,b]]){
  for(let n=0;n<8;n++){
   const data=randomBytes(128),ingress=sealReliable(key,{seq:n,ack:0,data});
   const output=resealLabHop({inputKey:key,outputKey:outKey,packet:ingress,hopSeq:id*8+n});
   assert.ok(output&&output.length===168);
   assert.equal(ingress.equals(output),false);
   assert.equal(openReliable(key,output),null);
   const opened=openReliable(outKey,output);
   assert.equal(opened.seq,id*8+n);
   assert.deepEqual(opened.data,data);
   decoded.push(output.toString('hex'));
  }
 }
 assert.equal(new Set(decoded).size,16);
 a.fill(0);b.fill(0);outKey.fill(0);
});
test('tamper, incorrect ingress key, cover and invalid keys are rejected',()=>{
 const a=randomBytes(32),out=randomBytes(32),wrong=randomBytes(32);
 const valid=sealReliable(a,{seq:0,ack:0,data:Buffer.from('synthetic')});
 assert.equal(resealLabHop({inputKey:wrong,outputKey:out,packet:valid,hopSeq:0}),null);
 const corrupt=Buffer.from(valid);corrupt[17]^=1;
 assert.equal(resealLabHop({inputKey:a,outputKey:out,packet:corrupt,hopSeq:0}),null);
 assert.equal(resealLabHop({inputKey:a,outputKey:out,packet:sealReliable(a,{ack:0}),hopSeq:0}),null);
 assert.throws(()=>resealLabHop({inputKey:a,outputKey:a,packet:valid,hopSeq:0}));
 assert.throws(()=>resealLabHop({inputKey:a,outputKey:out,packet:valid,hopSeq:8192}));
});
