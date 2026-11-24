import test from 'node:test';
import assert from 'node:assert/strict';
import {createSocket} from 'node:dgram';
import {randomBytes} from 'node:crypto';
import {mkdtemp,realpath,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {confirmScatteringCutover} from '../lib/quantic/scattering-cutover-lab.mjs';
import {openEpochFence} from '../lib/quantic/scattering-epoch-fence-lab.mjs';
async function pair(){
 const ss=[createSocket('udp4'),createSocket('udp4')];
 await Promise.all(ss.map(s=>new Promise((r,j)=>{s.once('error',j);s.bind(0,'127.0.0.1',r);})));
 await Promise.all(ss.map((s,i)=>new Promise((r,j)=>{s.once('error',j);s.connect(ss[1-i].address().port,'127.0.0.1',r);})));
 return ss;
}
const context={channel:'a'.repeat(96),generation:0,previous:'0'.repeat(96)};
const material=()=>({secret:randomBytes(32),epoch:randomBytes(32),generation:0,transcript:'b'.repeat(96)});
test('both UDP endpoints confirm readiness, wrong transcript and missing peer refuse', {timeout:12000},async()=>{
 const ss=await pair(),m=material();
 try{
  const options=i=>({socket:ss[i],role:i?'responder':'initiator',context,material:m,timeoutMs:2500});
  await Promise.all(ss.map((_,i)=>confirmScatteringCutover(options(i))));
  m.transcript='d'.repeat(96);
  const invalid=await Promise.allSettled([confirmScatteringCutover(options(0)),confirmScatteringCutover({...options(1),material:{...m,transcript:'c'.repeat(96)}})]);
  assert.ok(invalid.every(r=>r.status==='rejected'));
  m.transcript='e'.repeat(96);
  const abort=new AbortController();const waiting=confirmScatteringCutover({...options(0),signal:abort.signal});abort.abort();await assert.rejects(waiting);
  await assert.rejects(confirmScatteringCutover(options(0)),/not confirmed/);
 }finally{for(const s of ss)s.close();m.secret.fill(0);m.epoch.fill(0);}
});
test('staged generation remains blocked after reopening following a crash',{skip:process.platform!=='linux'},async()=>{
 const root=await realpath(await mkdtemp(join(tmpdir(),'scattering-cutover-'))),cfg={directory:join(root,'fence'),channel:context.channel,binding:'d'.repeat(96)};
 let f;
 try{
  f=openEpochFence({...cfg,createNew:true});const a=f.reserve(),m={generation:0,transcript:'b'.repeat(96)};
  f.stage(a,m);assert.equal(f.status().pending,true);assert.throws(()=>f.reserve());
  assert.throws(()=>f.commit({...a,context:{...a.context,generation:1,previous:m.transcript}},{generation:1,transcript:'c'.repeat(96)}));
  f.close();f=openEpochFence(cfg);assert.equal(f.status().pending,true);assert.throws(()=>f.reserve());
  assert.throws(()=>f.finish({...a,token:'0'.repeat(64)},m));assert.throws(()=>f.finish(a,{...m,transcript:'c'.repeat(96)}));
  f.finish(a,m);assert.equal(f.status().pending,false);assert.throws(()=>f.finish(a,m));
  const b=f.reserve();assert.equal(b.context.generation,1);assert.equal(b.context.previous,m.transcript);
  f.stage(b,{generation:1,transcript:'e'.repeat(96)});f.close();f=openEpochFence(cfg);assert.throws(()=>f.reserve());
 }finally{f?.close();await rm(root,{recursive:true,force:true});}
});
