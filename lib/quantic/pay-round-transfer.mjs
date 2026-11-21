// Single bounded volatile upload, for a certified view-change prepare only.
// Partial bytes have no authority; caller dispatches only after full validation.
// No keys, no arbitrary file IO, and no persistent upload state.
import {createHash,randomBytes} from 'node:crypto';
const check=v=>{if(!v)throw Error('Round transfer refused');};
const hex=/^[a-f0-9]{64}$/;
const exact=(o,k)=>o&&typeof o==='object'&&!Array.isArray(o)&&Object.keys(o).length===k.length&&k.every(x=>Object.hasOwn(o,x));
export const ROUND_TRANSFER_MAX=98304,ROUND_TRANSFER_CHUNK=18000;
const sha=b=>createHash('sha256').update(b).digest('hex');
export function createRoundUpload({clock=Date.now}={}){
 let active=null;
 function clear(){if(active){active.raw.fill(0);active=null;}}
 function expire(){if(active&&clock()>=active.deadline)clear();}
 return Object.freeze({
  begin(input){
   expire();
   check(!active&&exact(input,['size','digest'])&&Number.isInteger(input.size)&&input.size>32768&&input.size<=ROUND_TRANSFER_MAX&&typeof input.digest==='string'&&hex.test(input.digest));
   const id=randomBytes(32).toString('hex');
   active={id,digest:input.digest,raw:Buffer.alloc(input.size),offset:0,deadline:clock()+120000};
   return {id,offset:0};
  },
  chunk(input){
   expire();check(active&&exact(input,['id','offset','data'])&&input.id===active.id&&input.offset===active.offset);
   check(typeof input.data==='string'&&input.data.length<=24000&&/^[A-Za-z0-9_-]+$/.test(input.data));
   const b=Buffer.from(input.data,'base64url');
   try{
    check(b.toString('base64url')===input.data&&b.length===Math.min(ROUND_TRANSFER_CHUNK,active.raw.length-active.offset)&&b.length>0);
    b.copy(active.raw,active.offset);active.offset+=b.length;
    return {id:active.id,offset:active.offset};
   }finally{b.fill(0);}
  },
  finish(input){
   expire();check(active&&exact(input,['id'])&&input.id===active.id);
   try{
    check(active.offset===active.raw.length&&sha(active.raw)===active.digest);
    const payload=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(active.raw));
    check(exact(payload,['round','value','viewCertificate'])&&Number.isSafeInteger(payload.round)&&payload.round>0&&payload.viewCertificate?.round===payload.round);
    return payload;
   }finally{clear();}
  },
  clear
 });
}
export function encodeRoundPrepare(input){
 const raw=Buffer.from(JSON.stringify(input));
 check(raw.length>32768&&raw.length<=ROUND_TRANSFER_MAX);
 return {raw,size:raw.length,digest:sha(raw)};
}
