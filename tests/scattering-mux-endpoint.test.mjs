import test from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import {openEndpointSender,openEndpointReceiver,E2E_POLICY} from '../lib/quantic/scattering-mux-endpoint-lab.mjs';
import {openMultiplexSender,openMultiplexReceiver} from '../lib/quantic/scattering-multiplex-lab.mjs';
test('32 endpoints retain payload privacy even after routing layer decryption',()=>{
 const epoch=randomBytes(32),members=Array.from({length:32},(_,i)=>({id:'demo-'+i,secret:randomBytes(32)}));
 const route={epoch,direction:'a-b',members},gateway=openMultiplexSender(route),router=openMultiplexReceiver(route);
 const channels=members.map(m=>({epoch,from:m.id,to:'demo-destination',secret:randomBytes(32)}));
 const send=channels.map(openEndpointSender),recv=channels.map(openEndpointReceiver);
 try{
  const originals=members.map(()=>randomBytes(E2E_POLICY.payload));
  const opaque=send.map((s,i)=>s.seal(originals[i]));
  opaque.forEach((b,i)=>gateway.enqueue(members[i].id,b));
  for(let i=0;i<32;i++){
   const r=router.receive(gateway.nextSlot());assert.equal(r.member,members[i].id);assert.deepEqual(r.data,opaque[i]);
   assert.equal(r.data.length,78);
   const attacker=openEndpointReceiver({...channels[i],secret:members[i].secret});
   try{assert.equal(attacker.open(r.data),null);}finally{attacker.close();}
   assert.equal(recv[(i+1)%32].open(r.data),null);
   const altered=Buffer.from(r.data);altered[30]^=1;assert.equal(recv[i].open(altered),null);
   assert.deepEqual(recv[i].open(r.data),originals[i]);assert.equal(recv[i].open(r.data),null);
  }
  assert.equal(router.receive(gateway.nextSlot()),null);
 }finally{gateway.close();router.close();for(const c of [...send,...recv])c.close();}
});
test('end-to-end envelopes reject wrong direction, epoch, sequence and changed tag',()=>{
 const c={epoch:randomBytes(32),secret:randomBytes(32),from:'demo-alice',to:'demo-bob'};
 const s=openEndpointSender(c),r=openEndpointReceiver(c),wrong=openEndpointReceiver({...c,epoch:randomBytes(32)}),reverse=openEndpointReceiver({...c,from:c.to,to:c.from});
 try{
  const a=s.seal(Buffer.from('first')),b=s.seal(Buffer.from('second'));
  assert.equal(r.open(b),null);assert.equal(wrong.open(a),null);assert.equal(reverse.open(a),null);
  const bad=Buffer.from(a);bad[77]^=1;assert.equal(r.open(bad),null);
  assert.deepEqual(r.open(a),Buffer.from('first'));assert.deepEqual(r.open(b),Buffer.from('second'));
  assert.throws(()=>s.seal(Buffer.alloc(45)));assert.throws(()=>r.open(Buffer.alloc(77)));
 }finally{for(const o of [s,r,wrong,reverse])o.close();}
});
