// Isolated R&D experiment. Not a network decoder and not a signature verifier.
// A lossless binary representation of existing quorum certificates. No production use.
import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,createHash} from 'node:crypto';
import {createPayRoundLab} from '../lib/quantic/pay-round-lab.mjs';
import {packPayCertificate as pack,unpackPayCertificate as unpack,packPayVote,unpackPayVote,packPayFinal,unpackPayFinal} from '../lib/quantic/pay-certificate-wire-lab.mjs';
const HEADER=71,VOTE=3437;
const sha=b=>createHash('sha256').update(b).digest('hex');
const spki=k=>k.export({type:'spki',format:'der'});
for(const size of [16,31])test('lossless binary quorum '+size+' with genuine hybrid signature verification',t=>{
 const keys=Array.from({length:size},()=>{
  const cl=generateKeyPairSync('ed25519'),pq=generateKeyPairSync('ml-dsa-65'),a=spki(cl.publicKey),b=spki(pq.publicKey);
  const publicInfo={pin:sha(a),publicKey:a.toString('base64url'),pqPin:sha(b),pqPublicKey:b.toString('base64url')};
  return {publicInfo,credentials:{authorityPin:publicInfo.pin,classicalPrivateKey:cl.privateKey,pqPrivateKey:pq.privateKey}};
 });
 const lab=createPayRoundLab({network:'a'.repeat(64),height:1,previousRoot:'b'.repeat(64),authorities:keys.map(k=>k.publicInfo),committeeMode:true,admissionRound:true});
 const {quorum}=lab.committee,value='c'.repeat(64),nodes=keys.slice(0,quorum).map(k=>lab.openAuthority(k.credentials));
 const prepared={scope:lab.scope,round:0,value,votes:nodes.map(n=>n.prepare({round:0,value}))};
 const raw=pack(prepared,size),decoded=unpack(raw,size);
 assert.deepEqual(decoded,prepared);assert.deepEqual(lab.prepared(decoded),lab.prepared(prepared));
 const commit={scope:lab.scope,round:0,value,votes:nodes.map(n=>n.commit(decoded))};
 assert.equal(lab.finalized({prepared:decoded,commit:unpack(pack(commit,size),size)}).value,value);
 const final={prepared,commit},wire=packPayFinal(final,size);
 assert.deepEqual(unpackPayFinal(wire,size),final);
 assert.equal(lab.finalized(unpackPayFinal(wire,size)).value,value);
 assert.deepEqual(unpackPayVote(packPayVote(prepared.votes[0])),prepared.votes[0]);
 assert.throws(()=>unpackPayFinal(wire.subarray(0,-1),size));
 assert.throws(()=>unpackPayFinal(Buffer.concat([wire,Buffer.alloc(1)]),size));
 assert.throws(()=>unpackPayVote(Buffer.alloc(VOTE-1)));
 assert.throws(()=>packPayFinal({prepared,commit:{...commit,value:'e'.repeat(64)}},size));
 const tamperedFinal=Buffer.from(wire);tamperedFinal[wire.length-1]^=1;
 assert.throws(()=>lab.finalized(unpackPayFinal(tamperedFinal,size)));
 for(const offset of [4,36,HEADER+64,HEADER+128]){
  const changed=Buffer.from(raw);changed[offset]^=1;assert.throws(()=>lab.prepared(unpack(changed,size)));
 }
 for(const bad of [raw.subarray(0,-1),Buffer.concat([raw,Buffer.alloc(1)])])assert.throws(()=>unpack(bad,size));
 const duplicate=Buffer.from(raw);raw.copy(duplicate,HEADER+VOTE,HEADER,HEADER+VOTE);assert.throws(()=>unpack(duplicate,size));
 const json=Buffer.byteLength(JSON.stringify(prepared));assert.ok(raw.length<json*.75);
 t.diagnostic(JSON.stringify({size,quorum,jsonBytes:json,binaryBytes:raw.length,base64Bytes:Buffer.byteLength(raw.toString('base64url')),reduction:1-raw.length/json}));
});
