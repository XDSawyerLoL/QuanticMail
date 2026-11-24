import test from 'node:test';
import assert from 'node:assert/strict';
import {validateCarrierSchedule,runPrivateCarrierSchedule,PRIVATE_SCHEDULE_POLICY as policy} from '../standalone-relay/native-scattering-schedule.mjs';
const BASE=1700000000000;
function fixture(){
 const plans=Array.from({length:3},(_,i)=>({
  format:'quantic-private-scattering-host/v1',labOnly:true,
  pacerBinary:'/tmp/pacer',pacerSha256:'a'.repeat(64),listenIP:'127.0.0.1',listenPort:49001,peerIP:'127.0.0.1',peerPort:49003,periodUs:5000,
  carrier:{labOnly:true,role:'client',secretHex:String(i+1).repeat(64),epochHex:String(i+4).repeat(64),recvPort:49002,httpPort:49004,queueDir:'/tmp/queue-'+i,stateDir:'/tmp/state'}
 }));
 const slots=plans.map((_,i)=>{const startMs=BASE+1000+i*(policy.minSlotMs+policy.gapMs);
  return {startMs,endMs:startMs+policy.minSlotMs,file:'/tmp/slot-'+i+'.json',pin:'b'.repeat(64)};});
 return {spec:{format:'quantic-private-scattering-schedule/v1',labOnly:true,slots},plans};
}
test('reject any reused epoch/secret/spool, schedule drift or endpoint change',()=>{
 assert.equal(validateCarrierSchedule(fixture().spec,fixture().plans,{now:BASE}),true);
 for(const alter of [
  f=>f.plans[1].carrier.epochHex=f.plans[0].carrier.epochHex,
  f=>f.plans[1].carrier.secretHex=f.plans[0].carrier.secretHex,
  f=>f.plans[1].carrier.secretHex=f.plans[0].carrier.epochHex,
  f=>f.plans[1].carrier.queueDir=f.plans[0].carrier.queueDir,
  f=>f.plans[1].carrier.stateDir='/tmp/newstate',
  f=>f.plans[1].carrier.httpPort=49005,
  f=>f.plans[1].peerPort=49006,
  f=>f.spec.slots[1].startMs++,
  f=>f.spec.slots[0].startMs=BASE-1000,
  f=>f.spec.slots[1].file=f.spec.slots[0].file
 ]){const f=fixture();alter(f);assert.throws(()=>validateCarrierSchedule(f.spec,f.plans,{now:BASE}));}
});
test('scheduled rollover uses distinct keys and stable endpoint, no retry, drains each epoch',async()=>{
 const f=fixture();let now=BASE;const seen=[],closed=[],reports=[];
 const result=await runPrivateCarrierSchedule(f,{
  now:()=>now,monotonic:()=>now-BASE,pause:async ms=>{now+=ms;},
  startHost:async(p,{acceptUntil})=>{
   const i=seen.length;seen.push({secret:p.carrier.secretHex,epoch:p.carrier.epochHex,port:p.carrier.httpPort,now,acceptUntil});
   let close;const closedPromise=new Promise(r=>{close=r;});
   return {role:'client',closed:closedPromise,close:async()=>{closed.push(i);close({failed:false});}};
  },
  onSlot:s=>reports.push(s)
 });
 assert.deepEqual(closed,[0,1,2]);assert.equal(result.completedSlots,3);assert.equal(result.remoteTransportVerified,false);
 assert.equal(new Set(seen.map(x=>x.secret)).size,3);assert.equal(new Set(seen.map(x=>x.epoch)).size,3);
 assert.equal(new Set(seen.map(x=>x.port)).size,1);
 assert.deepEqual(seen.map(x=>x.now),f.spec.slots.map(s=>s.startMs));
 assert.deepEqual(seen.map(x=>x.acceptUntil),f.spec.slots.map(s=>s.endMs-policy.drainMs));
 assert.ok(reports.every(s=>s.remoteTransportVerified===false));
 assert.ok(f.plans.every(p=>p.carrier.secretHex===undefined&&p.carrier.epochHex===undefined));
});
test('a failed epoch or clock jump stops the whole schedule, never skips ahead or retries',async()=>{
 for(const mode of ['failure','clock']){
  const f=fixture();let now=BASE,mono=0,started=0,closed=0;
  await assert.rejects(runPrivateCarrierSchedule(f,{
   now:()=>now,monotonic:()=>mono,
   pause:async ms=>{now+=ms;mono+=ms;if(mode==='clock')now+=2000;},
   startHost:async()=>{started++;return {role:'client',closed:Promise.resolve({failed:true}),close:async()=>{closed++;}};}
  }));
  assert.equal(started,mode==='failure'?1:0);assert.equal(closed,started);
 }
});
