import test from 'node:test';
import assert from 'node:assert/strict';
import {makeGuiDepositApproval} from '../desktop/native-windows-gui-approval.mjs';

test('native GUI requires a second exact one-shot SEND authorization after durable sealing',async()=>{
 let prompts=0,reads=0;
 const approval=makeGuiDepositApproval(p=>{
  prompts++;
  assert.deepEqual(p,{phase:'sealed-awaiting-deposit-approval'});
 },async()=>{
  reads++;
  return 'SEND';
 });
 assert.equal(await approval(),true,'initial GUI approval was obtained by the caller');
 assert.equal(prompts,0);
 assert.equal(reads,0);
 assert.equal(await approval(),true);
 assert.equal(prompts,1);
 assert.equal(reads,1);
 assert.equal(await approval(),false,'third approval cannot silently trigger a new send');
 assert.equal(prompts,1);
 assert.equal(reads,1);
});
test('cancel, mismatched token and errors cannot authorize local deposit',async()=>{
 for(const token of ['send','SEND ','SEND\n','RETRY','',null,undefined,0,false]){
  let requested=0;
  const approve=makeGuiDepositApproval(()=>{requested++;},async()=>token);
  assert.equal(await approve(),true);
  assert.equal(await approve(),false,JSON.stringify(token));
  assert.equal(requested,1);
 }
 const cancelled=makeGuiDepositApproval(()=>{},async()=>{throw Error('private GUI pipe terminated');});
 assert.equal(await cancelled(),true);
 await assert.rejects(cancelled(),/terminated/);
 assert.equal(await cancelled(),false,'no retry after a disconnected private pipe');
});
test('missing GUI consent channel is refused',()=>{
 assert.throws(()=>makeGuiDepositApproval(null,async()=>true));
 assert.throws(()=>makeGuiDepositApproval(()=>{},null));
});
