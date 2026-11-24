import test from 'node:test';
import assert from 'node:assert/strict';
import {win32} from 'node:path';
import {receiveWindowsLabFromGUI} from '../desktop/native-windows-gui-receive.mjs';

const dir='C:\\Quantic\\private';
const address='alice~'+'a'.repeat(32)+'@quantic';
const deviceId='d-'+'b'.repeat(32);
const cfg={windowsLab:{dir},pqMode:{enabled:true,address,deviceId},
 windowsScattering:{enabled:true,address,deviceId,
 receiptKeyFile:win32.join(dir,'receipt.key'),endpoint:'http://127.0.0.1:49510/'}};
const id='a1478dbe-3003-4bb5-8fda-0123456789ab';
const expected=win32.join(dir,'receipt-a1478dbe30034bb58fda0123456789ab.json');

test('GUI receiver uses one fresh private receipt and reuses verified native ACK engine',async()=>{
 let count=0;
 const r=await receiveWindowsLabFromGUI(cfg,{},{
  makeId:()=>id,approve:async()=>true,receive:async (c,s,opts)=>{
   count++;assert.equal(c,cfg);assert.equal(opts.operation,'receive');
   assert.equal(opts.path,expected);
   return {status:'acknowledged',display:'Synthetic authenticated message'};
  }
 });
 assert.equal(count,1);
 assert.deepEqual(r,{status:'opened-and-acknowledged-on-local-relay',
  display:'Synthetic authenticated message',remoteDeliveryVerified:false});
});
test('empty and declined mail never show delivery success',async()=>{
 for(const status of ['empty','cancelled']){
  const r=await receiveWindowsLabFromGUI(cfg,{},{
   makeId:()=>id,approve:async()=>false,receive:async()=>({status})
  });
  assert.deepEqual(r,{status,remoteDeliveryVerified:false});
 }
});
test('invalid receipt ID, foreign endpoint, malformed result and native failure fail closed',async()=>{
 let touched=0;
 const receive=async()=>{touched++;return {status:'acknowledged'};};
 for(const makeId of [()=>'',()=>id+'\\..',()=>'0'.repeat(32),()=>id.replace('4bb5','0bb5')]){
  await assert.rejects(receiveWindowsLabFromGUI(cfg,{}, {approve:async()=>true,makeId,receive}));
 }
 assert.equal(touched,0);
 await assert.rejects(receiveWindowsLabFromGUI({...cfg,windowsScattering:{...cfg.windowsScattering,
  endpoint:'https://example.com/'}},{},{approve:async()=>true,makeId:()=>id,receive}));
 assert.equal(touched,0);
 await assert.rejects(receiveWindowsLabFromGUI(cfg,{},{
  approve:async()=>true,makeId:()=>id,receive
 }));
 await assert.rejects(receiveWindowsLabFromGUI(cfg,{},{
  approve:async()=>true,makeId:()=>id,receive:async()=>{throw Error('ambiguous ACK');}
 }),/ambiguous ACK/);
});
