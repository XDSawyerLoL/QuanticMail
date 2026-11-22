// Synthetic fixed-height reference cache. No network protocol, persistent trust,
// user identity, global availability guarantee or authorization by hash alone.
// Independently validate every reconstructed batch with existing hybrid verifier.
// Cache hits/misses are private local information; transport padding is separate.
import {createHash} from 'node:crypto';
import {openPayBatchLab} from './pay-batch-lab.mjs';
import {buildReferenceSketch,reconcileReferenceSketch} from './pay-reference-reconcile-lab.mjs';
import {encodePayBatchBinary,decodePayBatchBinary} from './pay-batch-binary-lab.mjs';
const MAX=1024,MAX_BYTES=4*1024*1024,REF=48,HEADER=78,ZERO='0'.repeat(64);
const MAGIC=Buffer.from('QBR1');
const check=x=>{if(!x)throw Error('Pay reference laboratory refused');};
const hex=(s,n)=>typeof s==='string'&&s.length===n&&/^[0-9a-f]+$/.test(s);
const safe=n=>Number.isSafeInteger(n)&&n>=0;
const sha=(scope,b)=>createHash('sha384').update('quantic-pay-proof-reference/lab/v1\0').update(Buffer.from(scope,'hex')).update(b).digest('hex');
function single(proof){return encodePayBatchBinary({proofs:[proof],time:0,value:ZERO});}
function readSingle(b){const p=decodePayBatchBinary(b);check(p.time===0&&p.value===ZERO&&p.proofs.length===1);return p.proofs[0];}
export function openPayReferenceLab({config,records=[]}){
 const lab=openPayBatchLab({config,records}),scope=lab.scope,cache=new Map();let bytes=0;
 function ref(p){return sha(scope,single(p));}
 function encode(m){
  check(m.scope===scope&&safe(m.time)&&hex(m.value,64)&&Array.isArray(m.refs)&&m.refs.length>=1&&m.refs.length<=MAX);
  check(m.refs.every((r,i)=>hex(r,REF*2)&&(i===0||m.refs[i-1]<r)));
  const b=Buffer.alloc(HEADER+m.refs.length*REF);
  MAGIC.copy(b);Buffer.from(scope,'hex').copy(b,4);b.writeBigUInt64BE(BigInt(m.time),36);Buffer.from(m.value,'hex').copy(b,44);b.writeUInt16BE(m.refs.length,76);
  m.refs.forEach((r,i)=>Buffer.from(r,'hex').copy(b,HEADER+i*REF));return b;
 }
 function decode(b){
  check(Buffer.isBuffer(b)&&b.length>=HEADER+REF&&b.length<=HEADER+MAX*REF&&b.subarray(0,4).equals(MAGIC));
  const n=b.readUInt16BE(76);check(n>=1&&n<=MAX&&b.length===HEADER+n*REF);
  const m={scope:b.subarray(4,36).toString('hex'),time:Number(b.readBigUInt64BE(36)),value:b.subarray(44,76).toString('hex'),refs:Array.from({length:n},(_,i)=>b.subarray(HEADER+i*REF,HEADER+(i+1)*REF).toString('hex'))};
  check(encode(m).equals(b));return m;
 }
 function stage(entries){
  const additions=new Map();let total=0;
  for(const [r,b] of entries){
   if(cache.has(r)){check(cache.get(r).equals(b));continue;}
   if(additions.has(r)){check(additions.get(r).equals(b));continue;}
   additions.set(r,b);total+=b.length;
  }
  check(cache.size+additions.size<=MAX&&bytes+total<=MAX_BYTES);
  for(const [r,b] of additions)cache.set(r,Buffer.from(b));bytes+=total;
 }
 function publish({proofs,time,value}){
  const p=lab.propose(proofs,time);check(p.value===value);
  const entries=proofs.map(proof=>{const b=single(proof);return [sha(scope,b),b];});
  const manifest=encode({scope,time,value,refs:entries.map(([r])=>r).sort()});stage(entries);return manifest;
 }
 function missing(manifest){return decode(manifest).refs.filter(r=>!cache.has(r));}
 function exportProof(manifest,r){
  const m=decode(manifest);check(hex(r,REF*2)&&m.refs.includes(r)&&cache.has(r));return Buffer.from(cache.get(r));
 }
 function recover(manifest,r,b){
  const m=decode(manifest);check(hex(r,REF*2)&&m.refs.includes(r)&&Buffer.isBuffer(b)&&b.length<=6000&&sha(scope,b)===r);
  const proof=readSingle(b);lab.propose([proof],m.time);stage([[r,b]]);
 }
 function resolve(manifest){
  const m=decode(manifest);check(m.refs.every(r=>cache.has(r)));
  const proofs=m.refs.map(r=>{const b=cache.get(r);check(sha(scope,b)===r);return readSingle(b);});
  const result=lab.propose(proofs,m.time);check(result.value===m.value);
  return result;
 }
 // Sketch and time/value metadata must be authenticated by the surrounding protocol.
 function sketch(manifest,width=64){return buildReferenceSketch({scope,refs:decode(manifest).refs,width});}
 function fromSketch({sketch,time,value}){
  const result=reconcileReferenceSketch({scope,localRefs:[...cache.keys()],sketch});
  return encode({scope,time,value,refs:result.refs});
 }
 return Object.freeze({scope,reference:ref,publish,missing,exportProof,recover,resolve,sketch,fromSketch,stats:()=>Object.freeze({entries:cache.size,bytes}),clear(){for(const b of cache.values())b.fill(0);cache.clear();bytes=0;}});
}
