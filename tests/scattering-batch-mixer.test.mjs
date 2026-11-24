import test from 'node:test';
import assert from 'node:assert/strict';
import {createScatteringBatchMixer} from '../lib/quantic/scattering-batch-mixer-lab.mjs';
const item=(n)=>({source:n%2,packet:Buffer.alloc(168,n)});
test('shuffles complete batches and retains each ciphertext exactly once',()=>{
 const out=[];
 const mixer=createScatteringBatchMixer({batchSize:4,draw:()=>0,
  onBatch:batch=>out.push(...batch.map(i=>i.packet[0]))});
 for(let n=1;n<=8;n++)mixer.add(item(n));
 assert.deepEqual(out,[2,3,4,1,6,7,8,5]);
 assert.deepEqual(mixer.stats(),{batchSize:4,pending:0,emitted:8,batches:2});
});
test('partial final batch can be flushed without emitting extra cells',()=>{
 const out=[];
 const mixer=createScatteringBatchMixer({batchSize:4,draw:()=>0,
  onBatch:batch=>out.push(...batch.map(x=>x.packet[0]))});
 mixer.add(item(1));mixer.add(item(2));
 assert.equal(mixer.stats().pending,2);
 assert.equal(mixer.drain(),2);
 assert.deepEqual(out,[2,1]);
 assert.equal(mixer.drain(),0);
});
test('fail closed on invalid frame, biased random generator or failed spool',()=>{
 const m=createScatteringBatchMixer({batchSize:2,onBatch:()=>{}});
 assert.throws(()=>m.add({source:0,packet:Buffer.alloc(167)}));
 assert.throws(()=>m.add({source:3,packet:Buffer.alloc(168)}));
 const broken=createScatteringBatchMixer({batchSize:2,draw:()=>100,onBatch:()=>{}});
 broken.add(item(1));
 assert.throws(()=>broken.add(item(2)),/shuffle randomness/);
 assert.equal(broken.stats().pending,2);
 const commitFailure=createScatteringBatchMixer({batchSize:2,onBatch:()=>{throw Error('disk full')}});
 commitFailure.add(item(1));
 assert.throws(()=>commitFailure.add(item(2)),/disk full/);
 assert.equal(commitFailure.stats().emitted,0);
 assert.equal(commitFailure.stats().pending,2);
});

test('sparse batch flush pads to fixed size without losing or duplicating real cells',()=>{
 const out=[];
 const mixer=createScatteringBatchMixer({batchSize:8,draw:()=>0,
  onBatch:batch=>out.push(batch)});
 for(let n=1;n<=4;n++)mixer.add(item(n));
 assert.equal(mixer.flushPadded(),4);
 assert.equal(out.length,1);
 assert.equal(out[0].length,8);
 assert.deepEqual(out[0].filter(x=>x.source!==null).map(x=>x.packet[0]).sort((a,b)=>a-b),[1,2,3,4]);
 assert.equal(out[0].filter(x=>x.source===null).length,4);
 assert.ok(out[0].every(x=>x.packet.length===168));
 assert.equal(mixer.flushPadded(),0);
 assert.deepEqual(mixer.stats(),{batchSize:8,pending:0,emitted:4,batches:1});
});
test('padded release preserves queued input when commit fails',()=>{
 let fail=true;
 const out=[];
 const mixer=createScatteringBatchMixer({batchSize:8,draw:()=>0,onBatch:batch=>{
  if(fail)throw Error('disk full');out.push(batch);
 }});
 mixer.add(item(1));
 assert.throws(()=>mixer.flushPadded(),/disk full/);
 assert.equal(mixer.stats().pending,1);
 assert.equal(mixer.stats().emitted,0);
 fail=false;
 assert.equal(mixer.flushPadded(),1);
 assert.equal(out[0].length,8);
});
