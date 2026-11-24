import test from 'node:test';
import assert from 'node:assert/strict';
import {startScatteringRotation,startWindowsScatteringRotation} from '../desktop/native-scattering-rotation.mjs';
const channel='a'.repeat(96);
function fixture(){
 let opened=0,retired=0,closed=0,authorized=0;
 const epochs=Array.from({length:4},(_,i)=>({config:{labOnly:true,role:'client',queueDir:'q'+i,stateDir:'s'+i}}));
 const signer={authorizeRenewal:async()=>{authorized++;return {expires:100000,attempts:4};},signHandshake:async()=>{},fence:{}};
 function carrier(generation){
  let resolve,done=false;const closedPromise=new Promise(r=>{resolve=r;});
  const close=async()=>{if(!done){done=true;closed++;resolve();}};
  return {generation,peerReady:true,closed:closedPromise,close,retire:async()=>{retired++;await close();}};
 }
 const start=async()=>carrier(opened++);
 const options={channel,role:'initiator',epochs,signer,periodMs:1000};
 return {options,start,carrier,counts:()=>({opened,retired,closed,authorized})};
}
test('rotation consumes at most four generations with one grant',async()=>{
 const f=fixture();
 const r=startScatteringRotation(f.options,{start:f.start,wait:async()=> 'rotate',now:()=>0});
 assert.deepEqual(await r.closed,{status:'authorization-budget-exhausted'});
 assert.deepEqual(f.counts(),{opened:4,retired:4,closed:4,authorized:1});
});
test('loss and uncertain operation halt without retry',async()=>{
 for(const reason of ['carrier-lost','authorization-expired']){
  const f=fixture(),r=startScatteringRotation(f.options,{start:f.start,wait:async()=>reason,now:()=>0});
  assert.deepEqual(await r.closed,{status:reason});assert.equal(f.counts().opened,1);assert.equal(f.counts().closed,1);
 }
 const f=fixture(),r=startScatteringRotation(f.options,{start:async()=>{const c=await f.start();return {...c,retire:async()=>{throw Error('operation pending');}};},wait:async()=> 'rotate',now:()=>0});
 assert.deepEqual(await r.closed,{status:'failed-no-retry'});assert.equal(f.counts().opened,1);assert.equal(f.counts().closed,1);
});
test('parent abort while starting closes late carrier and prevents rotation',async()=>{
 const f=fixture(),stop=new AbortController();let release,entered;
 const starting=new Promise(r=>{entered=r;});
 const r=startScatteringRotation({...f.options,signal:stop.signal},{start:async()=>{entered();await new Promise(r=>{release=r;});return f.start();},now:()=>0});
 await starting;stop.abort();release();
 assert.deepEqual(await r.closed,{status:'stopped'});assert.equal(f.counts().opened,1);assert.equal(f.counts().closed,1);
});
test('rejects reused queue and missing live Windows vault',()=>{
 const f=fixture();f.options.epochs[1].config.queueDir=f.options.epochs[0].config.queueDir;
 assert.throws(()=>startScatteringRotation(f.options));
 assert.throws(()=>startWindowsScatteringRotation({controller:{}}));
});
