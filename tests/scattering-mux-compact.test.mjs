import test from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes,createCipheriv,createDecipheriv} from 'node:crypto';
import {COMPACT_MUX,openCompactSender,openCompactReceiver,openOpaqueRouter} from '../lib/quantic/scattering-mux-compact-lab.mjs';
test('32 opaque routes, fixed-size encrypted outer cells and exact payload recovery',()=>{
 const epoch=randomBytes(32),configs=Array.from({length:32},()=>({secret:randomBytes(32),label:randomBytes(16),epoch,direction:'a-b'}));
 const s=configs.map(openCompactSender),r=configs.map(openCompactReceiver),router=openOpaqueRouter(configs.map(c=>c.label)),key=randomBytes(32);
 const expected=configs.map(()=>Array.from({length:10},()=>randomBytes(COMPACT_MUX.payload)));
 try{
  for(let i=0;i<32;i++)for(const b of expected[i])router.enqueue(configs[i].label,s[i].seal(b));
  for(let slot=0;slot<1000;slot++){
   const b=router.nextSlot(),nonce=randomBytes(12),p=Buffer.concat([Buffer.alloc(12),b]),enc=createCipheriv('aes-256-gcm',key,nonce);
   const packet=Buffer.concat([nonce,enc.update(p),enc.final(),enc.getAuthTag()]);assert.equal(packet.length,168);
   const dec=createDecipheriv('aes-256-gcm',key,packet.subarray(0,12));dec.setAuthTag(packet.subarray(-16));const inner=Buffer.concat([dec.update(packet.subarray(12,-16)),dec.final()]).subarray(12);
   if(slot<320){const i=slot%32;assert.deepEqual(r[i].open(inner),expected[i][Math.floor(slot/32)]);assert.equal(r[i].open(inner),null);}else for(const endpoint of r)assert.equal(endpoint.open(inner),null);
  }
  assert.deepEqual(router.stats(),{queued:0,slots:1000});
 }finally{router.close();for(const e of [...s,...r])e.close();key.fill(0);}
});
test('wrong route, keys, direction, epoch, tampering, order and bounds fail closed',()=>{
 const a={secret:randomBytes(32),label:randomBytes(16),epoch:randomBytes(32),direction:'a-b'},b={...a,label:randomBytes(16),secret:randomBytes(32)};
 const s=openCompactSender(a),r=openCompactReceiver(a),wrong=openCompactReceiver(b),wrongKey=openCompactReceiver({...a,secret:randomBytes(32)}),rev=openCompactReceiver({...a,direction:'b-a'}),stale=openCompactReceiver({...a,epoch:randomBytes(32)}),router=openOpaqueRouter([a.label,b.label]);
 try{
  const first=s.seal(Buffer.from('a')),second=s.seal(Buffer.from('b'));assert.equal(r.open(second),null);
  for(const e of [wrong,wrongKey,rev,stale])assert.equal(e.open(first),null);
  for(const o of [0,16,40,127]){const x=Buffer.from(first);x[o]^=1;assert.equal(r.open(x),null);}
  assert.throws(()=>router.enqueue(b.label,first));assert.deepEqual(r.open(first),Buffer.from('a'));assert.equal(r.open(first),null);assert.deepEqual(r.open(second),Buffer.from('b'));
  for(let i=0;i<32;i++)router.enqueue(a.label,first);assert.throws(()=>router.enqueue(a.label,first));
  assert.throws(()=>s.seal(Buffer.alloc(79)));assert.throws(()=>openOpaqueRouter([a.label,a.label]));
 }finally{for(const e of [s,r,wrong,wrongKey,rev,stale,router])e.close();}
});
