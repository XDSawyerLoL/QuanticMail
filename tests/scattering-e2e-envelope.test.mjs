import test from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import {openReliable,sealReliable} from '../labs/quantic-native/scattering/scattering-reliable-lab.mjs';
import {sealEndToEndLab,openEndToEndLab,sealNestedLab,openNestedLab,E2E_LAB} from '../lib/quantic/scattering-e2e-envelope-lab.mjs';
import {resealLabHop} from '../lib/quantic/scattering-hop-reseal-lab.mjs';

test('two senders retain end-to-end content across a re-encrypting lab relay with separate hop keys',()=>{
 const keys=[randomBytes(32),randomBytes(32),randomBytes(32)], e2e=randomBytes(32);
 let seqAtRelay=0;
 try{
  for(let senderId=0;senderId<2;senderId++){
   for(let seq=0;seq<24;seq++){
    const data=randomBytes(E2E_LAB.dataLength);
    const input=sealNestedLab({hopKey:keys[senderId],endToEndKey:e2e,senderId,seq,data});
    assert.equal(input.length,168);
    const outer=openReliable(keys[senderId],input);
    assert.equal(outer.data.length,E2E_LAB.innerLength);
    // Relay can read the inner encrypted blob, not its plaintext under either hop key.
    assert.equal(openEndToEndLab(keys[senderId],outer.data),null);
    assert.equal(openEndToEndLab(keys[2],outer.data),null);
    const output=resealLabHop({inputKey:keys[senderId],outputKey:keys[2],packet:input,hopSeq:seqAtRelay++});
    assert.equal(output.length,168);
    assert.equal(input.equals(output),false);
    assert.equal(openReliable(keys[senderId],output),null);
    assert.deepEqual(openNestedLab({hopKey:keys[2],endToEndKey:e2e,packet:output}),{senderId,seq,data});
    assert.equal(openNestedLab({hopKey:keys[2],endToEndKey:keys[2],packet:output}),null);
   }
  }
 }finally{for(const key of [...keys,e2e])key.fill(0);}
});
test('AES-GCM tamper or incorrect end-to-end key is rejected after hop authentication',()=>{
 const hop=randomBytes(32),e2e=randomBytes(32),wrong=randomBytes(32);
 try{
  const input=sealNestedLab({hopKey:hop,endToEndKey:e2e,senderId:1,seq:4,data:randomBytes(59)});
  const tamper=Buffer.from(input);tamper[40]^=0x80;
  assert.equal(openNestedLab({hopKey:hop,endToEndKey:e2e,packet:tamper}),null);
  assert.equal(openNestedLab({hopKey:hop,endToEndKey:wrong,packet:input}),null);
  const outer=openReliable(hop,input);
  const inner=Buffer.from(outer.data);inner[30]^=1;
  const authenticOuterWithInvalidInner=sealReliable(hop,{seq:4,ack:0,data:inner});
  assert.equal(openNestedLab({hopKey:hop,endToEndKey:e2e,packet:authenticOuterWithInvalidInner}),null);
  assert.equal(openEndToEndLab(e2e,Buffer.alloc(92)),null);
  assert.throws(()=>sealEndToEndLab(hop,{senderId:2,seq:3,data:randomBytes(59)}));
  assert.throws(()=>sealEndToEndLab(hop,{senderId:0,seq:8192,data:randomBytes(59)}));
  assert.throws(()=>sealEndToEndLab(hop,{senderId:0,seq:3,data:randomBytes(60)}));
 }finally{hop.fill(0);e2e.fill(0);wrong.fill(0);}
});
test('same app plaintext yields unlinkable inner ciphertext due to independently random nonce',()=>{
 const hop=randomBytes(32),e2e=randomBytes(32),data=Buffer.alloc(59,0x43);
 try{
  const a=sealNestedLab({hopKey:hop,endToEndKey:e2e,senderId:0,seq:1,data});
  const b=sealNestedLab({hopKey:hop,endToEndKey:e2e,senderId:0,seq:1,data});
  assert.ok(!a.equals(b));
  const ia=openReliable(hop,a).data, ib=openReliable(hop,b).data;
  assert.equal(ia.length,92);assert.equal(ib.length,92);
  assert.ok(!ia.equals(ib));
  assert.deepEqual(openEndToEndLab(e2e,ia),openEndToEndLab(e2e,ib));
 }finally{hop.fill(0);e2e.fill(0);}
});
