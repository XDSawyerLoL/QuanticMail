import test from 'node:test';
import assert from 'node:assert/strict';
import {createSocket} from 'node:dgram';
import {generateKeyPairSync,randomBytes,createHash} from 'node:crypto';
import {mkdtemp,realpath,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {openHybridSessionLab} from '../lib/quantic/scattering-session-lab.mjs';
import {packSession,unpackSession,sessionWireSize} from '../lib/quantic/scattering-session-wire-lab.mjs';
import {openEpochFence} from '../lib/quantic/scattering-epoch-fence-lab.mjs';
import {openCompactSender,openCompactReceiver,openOpaqueRouter} from '../lib/quantic/scattering-mux-compact-lab.mjs';
import {reliableCellStream,openReliable} from '../labs/quantic-native/scattering/scattering-reliable-lab.mjs';
function identity(){const a=generateKeyPairSync('ed25519'),b=generateKeyPairSync('ml-dsa-65');return {local:{classical:a.publicKey,pq:b.publicKey},privateKeys:{classical:a.privateKey,pq:b.privateKey}};}
const digest=b=>createHash('sha384').update(b).digest('hex');
const available=process.platform==='linux';
test('durable generations, binary hybrid handshake and opaque payload over actual local UDP', {skip:!available,timeout:25000},async t=>{
 const root=await realpath(await mkdtemp(join(tmpdir(),'quantic-session-'))),sockets=[],streams=[],fences=[],errors=[];
 const A=identity(),B=identity(),channel=randomBytes(48).toString('hex'),labels=[randomBytes(16),randomBytes(16)];
 const binding=role=>digest(Buffer.concat([Buffer.from(role),...([A,B].flatMap(x=>[x.local.classical,x.local.pq])).map(k=>k.export({type:'spki',format:'der'}))]));
 const configs=['initiator','responder'].map(role=>({directory:join(root,role),channel,binding:binding(role)}));
 const key=[randomBytes(32),randomBytes(32)];let dropped=0,packets=0;const measurements=[];
 try{
  for(const c of configs)fences.push(openEpochFence({...c,createNew:true}));
  for(let i=0;i<2;i++){const s=createSocket('udp4');sockets.push(s);await new Promise((res,rej)=>{s.once('error',rej);s.bind(0,'127.0.0.1',res);});}
  for(let i=0;i<2;i++){
   const c=reliableCellStream({sendKey:key[i],recvKey:key[1-i],compactPacing:true,dualProofPacing:true,publish:batch=>{
    assert.equal(batch.length,4);for(const b of batch){assert.equal(b.length,168);packets++;
     // Controlled fault injection in the fixture, never in the protocol.
     if(i===0&&dropped<2&&openReliable(key[i],b)?.seq!==null){dropped++;continue;}
     sockets[i].send(b,sockets[1-i].address().port,'127.0.0.1',e=>{if(e)errors.push(e.message);});}return true;
   }});c.stream.on('error',e=>errors.push(e.message));streams.push(c);sockets[i].on('message',b=>c.receive(b));
  }
  async function carry(i,b){const src=streams[i].stream,dst=streams[1-i].stream,parts=[];let size=0,onData,timer;
   const read=new Promise((res,rej)=>{onData=p=>{size+=p.length;if(size>b.length)return rej(Error('fixture frame overflow'));parts.push(p);if(size===b.length)res(Buffer.concat(parts));};dst.on('data',onData);});
   const write=new Promise((res,rej)=>src.write(b,e=>e?rej(e):res()));
   try{const [got]=await Promise.race([Promise.all([read,write]),new Promise((_,rej)=>{timer=setTimeout(()=>rej(Error('transfer timeout')),4000);})]);assert.deepEqual(got,b);return got;}finally{clearTimeout(timer);dst.off('data',onData);}
  }
  let oldFrame,oldContext;
  for(let gen=0;gen<3;gen++){
   const t0=performance.now(),res=fences.map(f=>f.reserve());assert.deepEqual(res[0].context,res[1].context);assert.equal(res[0].context.generation,gen);
   const a=openHybridSessionLab({role:'initiator',...A,peer:B.local,context:res[0].context});const b=openHybridSessionLab({role:'responder',...B,peer:A.local,context:res[1].context});
   let x,y,s,r,router;
   try{
    const h=a.begin(),hw=packSession('hello',h);assert.equal(hw.length,sessionWireSize('hello'));assert.throws(()=>unpackSession('response',hw));assert.throws(()=>unpackSession('hello',hw.subarray(0,-1)));
    const reply=b.respond(unpackSession('hello',await carry(0,hw))),rw=packSession('response',reply);
    const finish=a.finish(unpackSession('response',await carry(1,rw))),fw=packSession('finish',finish);
    b.accept(unpackSession('finish',await carry(0,fw)));x=a.take();y=b.take();assert.deepEqual(x,y);
    assert.throws(()=>fences[0].commit({...res[0],token:'0'.repeat(64)},x));
    // The fixture orchestrates both commits before permitting payload traffic.
    // This is not a distributed atomic cutover protocol.
    fences[0].commit(res[0],x);fences[1].commit(res[1],y);assert.throws(()=>fences[0].commit(res[0],x));
    s=openCompactSender({...x,label:labels[0],direction:'a-b'});r=openCompactReceiver({...y,label:labels[0],direction:'a-b'});router=openOpaqueRouter(labels);
    if(oldFrame)assert.equal(r.open(oldFrame),null);
    const data=randomBytes(78),frame=s.seal(data);router.enqueue(labels[0],frame);const got=await carry(0,router.nextSlot());assert.deepEqual(r.open(got),data);assert.equal(r.open(got),null);
    measurements.push({generation:gen,ms:Math.round(performance.now()-t0),jsonBytes:Buffer.byteLength(JSON.stringify([h,reply,finish])),binaryBytes:hw.length+rw.length+fw.length});oldFrame=frame;oldContext=res[0].context;
   }finally{a.close();b.close();s?.close();r?.close();router?.close();x?.secret.fill(0);y?.secret.fill(0);}
   for(let i=0;i<2;i++){fences[i].close();fences[i]=openEpochFence(configs[i]);assert.equal(fences[i].status().generation,gen);}
  }
  assert.equal(dropped,2);assert.ok(streams[0].stats.retransmitted>=2);assert.deepEqual(errors,[]);
  const pending=fences[0].reserve();fences[0].close();fences[0]=openEpochFence(configs[0]);assert.equal(fences[0].status().pending,true);assert.throws(()=>fences[0].reserve());
  assert.throws(()=>fences[0].commit({...pending,context:oldContext},{generation:2,transcript:'a'.repeat(96)}));
  assert.throws(()=>openEpochFence({...configs[0],binding:'f'.repeat(96)}));
  t.diagnostic('SESSION_INTEGRATED_V1 '+JSON.stringify({measurements,packets,dropped,retransmitted:streams[0].stats.retransmitted,pendingCrashRefused:true}));
 }finally{for(const f of fences)f.close();for(const s of streams)s.stream.destroy();for(const s of sockets)s.close();for(const k of key)k.fill(0);await rm(root,{recursive:true,force:true});}
});
