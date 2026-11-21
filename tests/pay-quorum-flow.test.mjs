import test from 'node:test';
import assert from 'node:assert/strict';
import {createLocalQuorumDemo} from '../scripts/quantic-pay-quorum-demo.mjs';
const operation={payeeId:'demo-shop',amount:'2.50',explicitConsent:true};
test('three separated witness states confirm two synthetic payments',async()=>{
 const flow=createLocalQuorumDemo({available:()=>[0,1,2]});
 await assert.rejects(flow.confirm({...operation,explicitConsent:false}));
 const a=await flow.confirm(operation);assert.equal(a.witnessCount,3);assert.equal(a.balanceCents,9750);
 const b=await flow.confirm(operation);assert.equal(b.proofCount,2);assert.equal(b.balanceCents,9500);assert.notEqual(a.nonce,b.nonce);
 assert.equal(b.realPaymentAuthorized,false);assert.equal(b.settlementVerified,false);
});
test('two pre-votes refuse confirmation; uncertain post-votes lock session without local debit',async()=>{
 const pre=createLocalQuorumDemo({available:()=>[0,1]});
 await assert.rejects(pre.confirm(operation));assert.equal(pre.snapshot().balanceCents,10000);assert.equal(pre.snapshot().halted,true);
 let calls=0;
 const post=createLocalQuorumDemo({available:phase=>phase==='append'?[0,1,2,3]:(++calls===1?[0,1,2,3]:[0,1])});
 await assert.rejects(post.confirm(operation));assert.equal(post.snapshot().balanceCents,10000);assert.equal(post.snapshot().halted,true);
 await assert.rejects(post.confirm(operation));
});
test('split witness history refuses post-confirmation even with four signatures',async()=>{
 const flow=createLocalQuorumDemo({available:phase=>phase==='append'?[0,1]:[0,1,2,3]});
 await assert.rejects(flow.confirm(operation));assert.equal(flow.snapshot().halted,true);assert.equal(flow.snapshot().proofCount,0);
});
