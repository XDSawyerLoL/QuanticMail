import test from 'node:test';
import assert from 'node:assert/strict';
import {simulateCover} from '../lib/quantic/scattering-cover-queue-lab.mjs';
test('fixed and Poisson profiles have traffic-independent observable slot counts in this ideal model',()=>{
 for(const mode of ['fixed','poisson']){
  const low=simulateCover({seconds:120,rate:50,load:5,mode,seed:7,trafficSeed:1});
  const high=simulateCover({seconds:120,rate:50,load:100,mode,seed:7,trafficSeed:33,burst:4});
  assert.deepEqual(low.trace,high.trace);
  for(const r of [low,high]){
   assert.equal(r.arrivals,r.useful+r.dropped+r.remaining);assert.ok(r.maxQueue<=512);
   assert.equal(r.slots,r.trace.reduce((a,b)=>a+b,0));
  }
  assert.ok(high.dropped>0);
 }
});
test('cover budget and queue percentiles under independent and burst arrivals',t=>{
 const profiles=[[200,20,'fixed',1],[50,20,'fixed',1],[50,20,'poisson',1],[20,20,'fixed',1],[50,40,'fixed',1],[50,40,'poisson',1],[50,40,'fixed',4],[50,40,'poisson',4],[20,5,'fixed',1],[20,5,'poisson',1]];
 for(const [rate,load,mode,burst] of profiles){
  const runs=Array.from({length:8},(_,i)=>simulateCover({rate,load,mode,burst,seed:i+50,trafficSeed:100+i}));
  for(const r of runs){
   assert.equal(r.arrivals,r.useful+r.dropped+r.remaining);
   assert.ok(r.maxQueue<=512&&r.p50ms<=r.p95ms&&r.p95ms<=r.p99ms);
   assert.ok(Math.abs(r.coverGoDay/(rate*168*2*86400/1e9)-1)<.06);
  }
  const result={rate,load,mode,burst,p95msWorst:Math.max(...runs.map(x=>x.p95ms)),p99msWorst:Math.max(...runs.map(x=>x.p99ms)),drops:runs.reduce((n,x)=>n+x.dropped,0),remainingMax:Math.max(...runs.map(x=>x.remaining)),arrivals:runs.reduce((n,x)=>n+x.arrivals,0),meanGoDay:runs.reduce((n,x)=>n+x.coverGoDay,0)/runs.length};
  t.diagnostic('COVER_QUEUE_V1 '+JSON.stringify(result));
  if(mode==='fixed'&&rate===50&&load===20){assert.equal(result.drops,0);assert.ok(result.p95msWorst<100);}
  if(mode==='fixed'&&rate===20&&load===20)assert.ok(result.p95msWorst>1000);
 }
});
test('pool accounting is conditional on independent arrivals and does not include client access links',()=>{
 const users=32,individualRate=2,aggregateRate=users*individualRate;
 const r=simulateCover({rate:100,load:aggregateRate,mode:'fixed'});
 const previous=users*200*168*2*86400/1e9;
 assert.ok(r.coverGoDay<previous/60);
 assert.equal(r.dropped,0);
});
