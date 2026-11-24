import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {buildReferenceSketch,reconcileReferenceSketch} from '../lib/quantic/pay-reference-reconcile-lab.mjs';
const scope='a'.repeat(64),ref=i=>createHash('sha384').update('synthetic:'+i).digest('hex');
const refs=Array.from({length:1000},(_,i)=>ref(i));
test('IBLT reconciliation resolves missing and extra references, with bounded failure rather than partial results',t=>{
 for(const [missing,extra,width] of [[0,0,32],[1,0,32],[10,3,64],[50,10,256],[100,20,512]]){
  let successes=0;const local=[...refs.slice(missing),...Array.from({length:extra},(_,i)=>ref(2000+i))];
  for(let seed=0;seed<32;seed++){
   const sketch=buildReferenceSketch({scope,refs,width,salt:Buffer.alloc(16,seed)});
   let r;try{r=reconcileReferenceSketch({scope,localRefs:local,sketch});}catch(e){assert.match(e.message,/Reconciliation refused/);continue;}
   assert.deepEqual(r.refs,[...refs].sort());assert.deepEqual(r.missing,refs.slice(0,missing).sort());assert.deepEqual(r.extra,local.slice(1000-missing).sort());successes++;
   assert.equal(sketch.length,104+66*width);
  }
  assert.ok(successes>=28,'insufficient reconciliation success: '+successes);
  t.diagnostic('REFERENCE_IBLT_V1 '+JSON.stringify({references:1000,missing,extra,width,bytes:104+66*width,successes,trials:32}));
 }
 const sketch=buildReferenceSketch({scope,refs,width:32,salt:Buffer.alloc(16)});
 assert.throws(()=>reconcileReferenceSketch({scope,localRefs:[],sketch}));
 assert.throws(()=>reconcileReferenceSketch({scope:'b'.repeat(64),localRefs:refs,sketch}));
 const corrupted=Buffer.from(sketch);corrupted[56]^=1;
 assert.throws(()=>reconcileReferenceSketch({scope,localRefs:refs,sketch:corrupted}));
 const negative=Buffer.from(sketch);negative.writeInt16BE(-1,104);
 assert.throws(()=>reconcileReferenceSketch({scope,localRefs:refs,sketch:negative}));
 assert.throws(()=>reconcileReferenceSketch({scope,localRefs:refs,sketch:sketch.subarray(0,-1)}));
 assert.throws(()=>buildReferenceSketch({scope,refs:[refs[0],refs[0]],width:32}));
 assert.throws(()=>buildReferenceSketch({scope,refs,width:1024}));
});
