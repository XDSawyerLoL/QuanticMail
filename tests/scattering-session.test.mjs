import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,randomBytes} from 'node:crypto';
import {fragmentSession,openSessionAssembly} from '../lib/quantic/scattering-session-udp-bootstrap-lab.mjs';
import {openHybridSessionLab} from '../lib/quantic/scattering-session-lab.mjs';
import {openCompactSender,openCompactReceiver,openOpaqueRouter} from '../lib/quantic/scattering-mux-compact-lab.mjs';
function identity(){const a=generateKeyPairSync('ed25519'),b=generateKeyPairSync('ml-dsa-65');return {local:{classical:a.publicKey,pq:b.publicKey},privateKeys:{classical:a.privateKey,pq:b.privateKey}};}
const A=identity(),B=identity(),C=identity();
const initial=()=>({channel:randomBytes(48).toString('hex'),generation:0,previous:'0'.repeat(96)});
function pair(context=initial()){return [openHybridSessionLab({role:'initiator',...A,peer:B.local,context}),openHybridSessionLab({role:'responder',...B,peer:A.local,context})];}
function negotiate(context){const [a,b]=pair(context);try{const h=a.begin(),r=b.respond(h),f=a.finish(r);b.accept(f);const x=a.take(),y=b.take();assert.deepEqual(x,y);return {x,y,wire:Buffer.byteLength(JSON.stringify([h,r,f]))};}finally{a.close();b.close();}}
const flip=s=>(s[0]==='A'?'B':'A')+s.slice(1);
test('32 independently authenticated hybrid sessions, opaque multiplex and fresh rekey',t=>{
 const contexts=Array.from({length:32},initial),start=performance.now(),sessions=contexts.map(negotiate),elapsed=performance.now()-start;
 const labels=contexts.map(()=>randomBytes(16));const route=openOpaqueRouter(labels),direction='a-b';
 const send=[],recv=[];try{
  for(let i=0;i<32;i++){
   send.push(openCompactSender({...sessions[i].x,label:labels[i],direction}));recv.push(openCompactReceiver({...sessions[i].y,label:labels[i],direction}));
   route.enqueue(labels[i],send[i].seal(Buffer.alloc(78,i)));
  }
  for(let i=0;i<32;i++){const b=route.nextSlot();assert.equal(b.length,128);assert.deepEqual(recv[i].open(b),Buffer.alloc(78,i));assert.equal(recv[i].open(b),null);}
  const old=send[0].seal(Buffer.from('old')),next=negotiate({...contexts[0],generation:1,previous:sessions[0].x.transcript});
  assert.notDeepEqual(next.x.secret,sessions[0].x.secret);assert.notDeepEqual(next.x.epoch,sessions[0].x.epoch);
  const s=openCompactSender({...next.x,label:labels[0],direction}),r=openCompactReceiver({...next.y,label:labels[0],direction});
  try{assert.equal(r.open(old),null);const fresh=s.seal(Buffer.from('new'));assert.equal(recv[0].open(fresh),null);assert.deepEqual(r.open(fresh),Buffer.from('new'));}finally{s.close();r.close();next.x.secret.fill(0);next.y.secret.fill(0);}
  t.diagnostic('HYBRID_SESSION_LAB '+JSON.stringify({sessions:32,handshakeMs:elapsed,meanMs:elapsed/32,wireBytes:sessions[0].wire,payload:78}));
 }finally{route.close();for(const e of [...send,...recv])e.close();for(const {x,y} of sessions){x.secret.fill(0);y.secret.fill(0);}}
});
test('signature tampering, transcript context, key confirmation and early release fail closed',()=>{
 for(const field of ['classical','pq']){const [a,b]=pair();const h=a.begin();h.sig[field]=flip(h.sig[field]);assert.throws(()=>b.respond(h));assert.throws(()=>b.take());a.close();}
 for(const field of ['classical','pq']){const [a,b]=pair();const r=b.respond(a.begin());r.sig[field]=flip(r.sig[field]);assert.throws(()=>a.finish(r));assert.throws(()=>a.take());b.close();}
 {const [a,b]=pair();const r=b.respond(a.begin());r.body.ciphertext=flip(r.body.ciphertext);assert.throws(()=>a.finish(r));b.close();}
 {const [a,b]=pair();const r=b.respond(a.begin());r.confirm=flip(r.confirm);assert.throws(()=>a.finish(r));b.close();}
 {const [a,b]=pair();const f=a.finish(b.respond(a.begin()));f.confirm=flip(f.confirm);assert.throws(()=>b.accept(f));assert.throws(()=>b.take());a.close();}
 {const [a,b]=pair();b.respond(a.begin());assert.throws(()=>b.take());a.close();}
 {const ctx=initial(),[a,b]=pair(ctx),replayed=openHybridSessionLab({role:'responder',...B,peer:A.local,context:{...ctx,generation:1,previous:'a'.repeat(96)}});assert.throws(()=>replayed.respond(a.begin()));a.close();b.close();}
 {const ctx=initial(),[a,b]=pair(ctx),impostor=openHybridSessionLab({role:'responder',...B,peer:C.local,context:ctx});assert.throws(()=>impostor.respond(a.begin()));a.close();b.close();}
 {const [a,b]=pair();b.accept(a.finish(b.respond(a.begin())));a.take().secret.fill(0);assert.throws(()=>a.take());b.close();}
});

test('pinned P-256 and ML-DSA device keys negotiate without wire algorithm selection',()=>{
 const device=()=>{const a=generateKeyPairSync('ec',{namedCurve:'prime256v1'}),b=generateKeyPairSync('ml-dsa-65');return {local:{classical:a.publicKey,pq:b.publicKey},privateKeys:{classical:a.privateKey,pq:b.privateKey}};};
 const D=device(),E=device(),F=device(),context=initial();
 const make=(role,self,other)=>openHybridSessionLab({role,...self,peer:other.local,context});
 let a=make('initiator',D,E),b=make('responder',E,D),x,y;
 try{
  const h=a.begin(),r=b.respond(h),f=a.finish(r);b.accept(f);x=a.take();y=b.take();assert.deepEqual(x,y);
 }finally{a.close();b.close();x?.secret.fill(0);y?.secret.fill(0);x?.epoch.fill(0);y?.epoch.fill(0);}
 a=make('initiator',D,E);b=make('responder',E,F);
 try{assert.throws(()=>b.respond(a.begin()));assert.throws(()=>b.take());}finally{a.close();b.close();}
 a=make('initiator',D,E);b=make('responder',E,D);
 try{const h=a.begin();h.sig.classical=flip(h.sig.classical);assert.throws(()=>b.respond(h));assert.throws(()=>b.take());}finally{a.close();b.close();}
 const wrong=generateKeyPairSync('ec',{namedCurve:'secp384r1'});
 assert.throws(()=>openHybridSessionLab({role:'initiator',local:{classical:wrong.publicKey,pq:D.local.pq},privateKeys:{classical:wrong.privateKey,pq:D.privateKeys.pq},peer:E.local,context}));
});

test('public UDP bootstrap fragments are bounded, tolerate reordering and exact duplicates, reject conflicts and wrong context',()=>{
 const ctx=initial(),[a,b]=pair(ctx);
 try{
  const hello=a.begin(),packets=fragmentSession('hello',hello,ctx);
  assert.equal(packets.length,5);assert.ok(packets.every(p=>p.length<=1048));
  const assembler=openSessionAssembly('hello',ctx);
  const wrong=fragmentSession('hello',hello,initial());
  for(const p of wrong)assert.equal(assembler.push(p),null);
  const oversized=Buffer.alloc(1049);assert.equal(assembler.push(oversized),null);
  assert.equal(assembler.push(packets[4]),null);
  assert.equal(assembler.push(packets[4]),null);
  for(let i=3;i>0;i--)assert.equal(assembler.push(packets[i]),null);
  assert.deepEqual(assembler.push(packets[0]),hello);
  assert.equal(assembler.push(packets[0]),null);
  const conflict=openSessionAssembly('hello',ctx);
  assert.equal(conflict.push(packets[0]),null);
  const changed=Buffer.from(packets[0]);changed[24]^=1;
  assert.throws(()=>conflict.push(changed),/Conflicting/);
  assert.equal(conflict.push(packets[1]),null);
  const altered=openSessionAssembly('hello',ctx);
  // A well-formed assembled frame is still untrusted until signatures pass.
  const bad=Buffer.from(packets[0]);bad[28]^=1;
  assert.equal(altered.push(bad),null);
  for(let i=1;i<4;i++)assert.equal(altered.push(packets[i]),null);
  assert.throws(()=>b.respond(altered.push(packets[4])));
  assert.throws(()=>b.take());
 }finally{a.close();b.close();}
});
