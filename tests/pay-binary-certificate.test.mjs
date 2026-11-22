// Isolated R&D experiment. Not a network decoder and not a signature verifier.
// A lossless binary representation of existing quorum certificates. No production use.
import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,createHash} from 'node:crypto';
import {createPayRoundLab} from '../lib/quantic/pay-round-lab.mjs';
import {payCommittee} from '../lib/quantic/pay-committee.mjs';
const check=v=>{if(!v)throw Error('Binary certificate refused');};
const exact=(o,keys)=>o&&typeof o==='object'&&!Array.isArray(o)&&Object.keys(o).length===keys.length&&keys.every(k=>Object.hasOwn(o,k));
const hex=v=>typeof v==='string'&&/^[0-9a-f]{64}$/.test(v);
const sig=(s,n)=>{check(typeof s==='string'&&s.length===Math.ceil(n*8/6)&&/^[A-Za-z0-9_-]+$/.test(s));const b=Buffer.from(s,'base64url');check(b.length===n&&b.toString('base64url')===s);return b;};
const HEADER=71,VOTE=3437,MAGIC=Buffer.from('QBC1');
function pack(c,size){
 const {quorum}=payCommittee(size);
 check(exact(c,['scope','round','value','votes'])&&hex(c.scope)&&hex(c.value)&&Number.isInteger(c.round)&&c.round>=0&&c.round<=1024&&Array.isArray(c.votes)&&c.votes.length>=quorum&&c.votes.length<=size);
 const b=Buffer.alloc(HEADER+c.votes.length*VOTE);
 MAGIC.copy(b);Buffer.from(c.scope,'hex').copy(b,4);Buffer.from(c.value,'hex').copy(b,36);b.writeUInt16BE(c.round,68);b[70]=c.votes.length;
 const seen=new Set(),pqSeen=new Set();
 for(const [i,v] of c.votes.entries()){
  check(exact(v,['pin','pqPin','signature','pqSignature'])&&hex(v.pin)&&hex(v.pqPin)&&!seen.has(v.pin)&&!pqSeen.has(v.pqPin));
  seen.add(v.pin);pqSeen.add(v.pqPin);const o=HEADER+i*VOTE;
  Buffer.from(v.pin,'hex').copy(b,o);Buffer.from(v.pqPin,'hex').copy(b,o+32);
  sig(v.signature,64).copy(b,o+64);sig(v.pqSignature,3309).copy(b,o+128);
 }
 return b;
}
function unpack(b,size){
 const {quorum}=payCommittee(size);
 check(Buffer.isBuffer(b)&&b.length>=HEADER&&b.subarray(0,4).equals(MAGIC));
 const round=b.readUInt16BE(68),count=b[70];check(round<=1024&&count>=quorum&&count<=size&&b.length===HEADER+VOTE*count);
 const votes=[],seen=new Set(),pqSeen=new Set();
 for(let i=0;i<count;i++){
  const o=HEADER+i*VOTE,pin=b.subarray(o,o+32).toString('hex'),pqPin=b.subarray(o+32,o+64).toString('hex');
  check(!seen.has(pin)&&!pqSeen.has(pqPin));seen.add(pin);pqSeen.add(pqPin);
  votes.push({pin,pqPin,signature:b.subarray(o+64,o+128).toString('base64url'),pqSignature:b.subarray(o+128,o+VOTE).toString('base64url')});
 }
 return {scope:b.subarray(4,36).toString('hex'),round,value:b.subarray(36,68).toString('hex'),votes};
}
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
 for(const offset of [4,36,HEADER+64,HEADER+128]){
  const changed=Buffer.from(raw);changed[offset]^=1;assert.throws(()=>lab.prepared(unpack(changed,size)));
 }
 for(const bad of [raw.subarray(0,-1),Buffer.concat([raw,Buffer.alloc(1)])])assert.throws(()=>unpack(bad,size));
 const duplicate=Buffer.from(raw);raw.copy(duplicate,HEADER+VOTE,HEADER,HEADER+VOTE);assert.throws(()=>unpack(duplicate,size));
 const json=Buffer.byteLength(JSON.stringify(prepared));assert.ok(raw.length<json*.75);
 t.diagnostic(JSON.stringify({size,quorum,jsonBytes:json,binaryBytes:raw.length,base64Bytes:Buffer.byteLength(raw.toString('base64url')),reduction:1-raw.length/json}));
});
