import test from 'node:test';
import assert from 'node:assert/strict';
import {handleHybridGuiCommand} from '../desktop/native-windows-hybrid-gui.mjs';
const peer='bob~'+'a'.repeat(32)+'@quantic';
const config={windowsLab:{dir:'C:\\Quantic\\private'},managedHybridScattering:{peerAddress:peer}};
const id='a1478dbe-3003-4bb5-8fda-0123456789ab';
function fixture(token){
 const phases=[];let sent=0,saved=0;
 const options={config,contacts:[],storage:{},makeId:()=>id,decision:async()=>token,publish:x=>phases.push(x.phase),
 save:async()=>{saved++;return {file:'draft-'+id.replaceAll('-','')+'.json'};},
 session:{status:()=> 'ready',compose:async o=>{assert.ok(await o.approve());if(!await o.approve())return {status:'saved-not-sent'};assert.equal(await o.approve(),false);sent++;return {status:'deposited',relayStatus:'queued'};},
 mail:async o=>{if(o.operation==='receive'){if(!await o.approve())return {status:'cancelled'};return {status:'acknowledged',display:'Synthetic'};}sent++;return {status:'deposited',digest:o.expectedDigest};}}};
 return {options,phases,counts:()=>({sent,saved})};
}
test('send uses shared session and separate exact deposit approval',async()=>{
 for(const token of ['SEND','CANCEL','send']){
  const f=fixture(token),r=await handleHybridGuiCommand({...f.options,command:{op:'send',fields:{to:peer,subject:'test',body:'test'}}});
  assert.deepEqual(f.phases,['draft-saved','sealed-awaiting-deposit-approval']);
  assert.equal(r.status,token==='SEND'?'queued-on-local-relay':'encrypted-saved-not-sent');assert.equal(r.remoteDeliveryVerified,false);
  assert.equal(f.counts().sent,token==='SEND'?1:0);
 }
});
test('rejects foreign peer, unexpected fields, nonready session; receive requires OPEN',async()=>{
 const f=fixture('CANCEL');
 for(const command of [{op:'send',fields:{to:'foreign',subject:'test',body:'test'}},{op:'receive',extra:true},{op:'unknown'}])await assert.rejects(handleHybridGuiCommand({...f.options,command}));
 assert.equal(f.counts().saved,0);
 assert.equal((await handleHybridGuiCommand({...f.options,command:{op:'receive'}})).status,'cancelled');
 const g=fixture('OPEN');assert.equal((await handleHybridGuiCommand({...g.options,command:{op:'receive'}})).display,'Synthetic');
 await assert.rejects(handleHybridGuiCommand({...g.options,session:{status:()=> 'negotiating'},command:{op:'receive'}}));
});
test('explicit retry references only original digest and private wire',async()=>{
 const f=fixture('SEND'),digest='a'.repeat(64);
 assert.equal((await handleHybridGuiCommand({...f.options,command:{op:'retry',selection:{name:'wire-original.json',digest}}})).digest,digest);
 await assert.rejects(handleHybridGuiCommand({...f.options,command:{op:'retry',selection:{name:'../wire-original.json',digest}}}));
 assert.equal(f.counts().sent,1);
});
