// Lossless synthetic wire encoding; the existing consensus MUST verify all
// decoded signatures, pins, phases and certificate scope before use.
import {payCommittee} from './pay-committee.mjs';
const check=v=>{if(!v)throw Error('Binary certificate refused');};
const exact=(o,keys)=>o&&typeof o==='object'&&!Array.isArray(o)&&Object.keys(o).length===keys.length&&keys.every(k=>Object.hasOwn(o,k));
const hex=v=>typeof v==='string'&&/^[0-9a-f]{64}$/.test(v);
const sig=(s,n)=>{check(typeof s==='string'&&s.length===Math.ceil(n*8/6)&&/^[A-Za-z0-9_-]+$/.test(s));const b=Buffer.from(s,'base64url');check(b.length===n&&b.toString('base64url')===s);return b;};
const HEADER=71,VOTE=3437,MAGIC=Buffer.from('QBC1');
export function packPayCertificate(c,size){
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
export function unpackPayCertificate(b,size){
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

export function packPayVote(v){
 check(exact(v,['pin','pqPin','signature','pqSignature'])&&hex(v.pin)&&hex(v.pqPin));
 return Buffer.concat([Buffer.from(v.pin,'hex'),Buffer.from(v.pqPin,'hex'),sig(v.signature,64),sig(v.pqSignature,3309)]);
}
export function unpackPayVote(b){
 check(Buffer.isBuffer(b)&&b.length===VOTE);
 return {pin:b.subarray(0,32).toString('hex'),pqPin:b.subarray(32,64).toString('hex'),signature:b.subarray(64,128).toString('base64url'),pqSignature:b.subarray(128).toString('base64url')};
}
export function packPayFinal(c,size){
 check(exact(c,['prepared','commit'])&&c.prepared.scope===c.commit.scope&&c.prepared.round===c.commit.round&&c.prepared.value===c.commit.value);
 return Buffer.concat([packPayCertificate(c.prepared,size),packPayCertificate(c.commit,size)]);
}
export function unpackPayFinal(b,size){
 check(Buffer.isBuffer(b)&&b.length>=2*HEADER&&b.length<=2*(HEADER+31*VOTE));const split=HEADER+b[70]*VOTE;
 const prepared=unpackPayCertificate(b.subarray(0,split),size),commit=unpackPayCertificate(b.subarray(split),size);
 const c={prepared,commit};check(packPayFinal(c,size).equals(b));return c;
}
