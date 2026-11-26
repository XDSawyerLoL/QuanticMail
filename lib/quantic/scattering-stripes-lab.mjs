// Synthetic fixed-profile multi-lane transfer laboratory. Does not provision
// remote peers or authenticate the manifest: independent application consensus
// still must verify the entire reconstructed message. No production fallback.
import {createHash} from 'node:crypto';
const MAX=4*1024*1024,STRIPE=8192;
const check=v=>{if(!v)throw Error('Scattering stripe refused');};
const sha=b=>createHash('sha256').update(b).digest('hex');
const hex=v=>typeof v==='string'&&/^[0-9a-f]{64}$/.test(v);
const exact=(o,k)=>o&&typeof o==='object'&&!Array.isArray(o)&&Object.keys(o).length===k.length&&k.every(x=>Object.hasOwn(o,x));
export function stripeLengths(size,lanes){
 check([1,2,4].includes(lanes)&&Number.isSafeInteger(size)&&size>0&&size<=MAX);
 const lengths=Array(lanes).fill(0);
 for(let o=0,i=0;o<size;o+=STRIPE,i++)lengths[i%lanes]+=Math.min(STRIPE,size-o);
 return lengths;
}
export function splitScatteringLab(bytes,lanes){
 check(Buffer.isBuffer(bytes));const lengths=stripeLengths(bytes.length,lanes),parts=lengths.map(n=>Buffer.alloc(n)),offsets=Array(lanes).fill(0);
 for(let o=0,i=0;o<bytes.length;o+=STRIPE,i++){
  const j=i%lanes,end=Math.min(bytes.length,o+STRIPE);bytes.copy(parts[j],offsets[j],o,end);offsets[j]+=end-o;
 }
 const manifest=Object.freeze({format:'quantic-scattering-stripes-lab/v1',size:bytes.length,lanes,digest:sha(bytes)});
 return {manifest,parts};
}
export function joinScatteringLab(manifest,parts){
 check(exact(manifest,['format','size','lanes','digest'])&&manifest.format==='quantic-scattering-stripes-lab/v1'&&hex(manifest.digest));
 const lengths=stripeLengths(manifest.size,manifest.lanes);check(Array.isArray(parts)&&parts.length===manifest.lanes&&parts.every((b,i)=>Buffer.isBuffer(b)&&b.length===lengths[i]));
 const result=Buffer.alloc(manifest.size),offsets=lengths.map(()=>0);
 for(let o=0,i=0;o<result.length;o+=STRIPE,i++){
  const j=i%manifest.lanes,n=Math.min(STRIPE,result.length-o);parts[j].copy(result,o,offsets[j],offsets[j]+n);offsets[j]+=n;
 }
 if(sha(result)!==manifest.digest){result.fill(0);throw Error('Scattering stripe digest mismatch');}return result;
}
