// Separate local 256-bit key; no key in receipt, browser or relay.
import {createCipheriv,createDecipheriv,randomBytes} from 'node:crypto';
import {open,constants} from 'node:fs/promises';
import {isAbsolute,dirname} from 'node:path';
const check=x=>{if(!x)throw Error('Encrypted local receipt refused');};
const idRE=/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const hashRE=/^[0-9a-f]{64}$/;
const addr=/^[a-z0-9][a-z0-9._-]{2,31}~[a-f0-9]{32}@quantic$/;
const dev=/^d-[a-f0-9]{32}$/;
function metadata(p){
 check(idRE.test(p.id)&&hashRE.test(p.digest)&&addr.test(p.address)&&dev.test(p.deviceId));
 return Buffer.from(JSON.stringify(['quantic-local-receipt/v1',p.address,p.deviceId,p.id,p.digest]));
}
function bytes(s,min,max){
 check(typeof s==='string'&&s.length<=Math.ceil(max/3)*4&&/^[A-Za-z0-9_-]+$/.test(s));
 const b=Buffer.from(s,'base64url');check(b.length>=min&&b.length<=max&&b.toString('base64url')===s);return b;
}
export async function readReceiptKey(path){
 check(typeof path==='string'&&isAbsolute(path)&&typeof process.getuid==='function');
 const f=await open(path,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
 try{
  const s=await f.stat();check(s.isFile()&&s.uid===process.getuid()&&(s.mode&0o077)===0&&s.size===32);
  const b=Buffer.alloc(33);let n=0;
  while(n<b.length){const r=await f.read(b,n,b.length-n,null);if(!r.bytesRead)break;n+=r.bytesRead;}
  if(n!==32){b.fill(0);throw Error('invalid receipt key');}
  return b.subarray(0,32);
 }finally{await f.close();}
}
function payloadOK(p){return p&&Object.keys(p).length===2&&typeof p.subject==='string'&&typeof p.body==='string'&&Buffer.byteLength(JSON.stringify(p))<=8192;}
export function sealReceipt(key,scope,item,payload){
 check(Buffer.isBuffer(key)&&key.length===32&&payloadOK(payload));
 const p={format:'quantic-local-receipt',version:1,address:scope.address,deviceId:scope.deviceId,id:item.id,digest:item.digest};
 const aad=metadata(p),iv=randomBytes(12),raw=Buffer.from(JSON.stringify(payload));
 try{
  const cipher=createCipheriv('aes-256-gcm',key,iv);cipher.setAAD(aad);
  const out=Buffer.concat([cipher.update(raw),cipher.final()]);
  return {...p,iv:iv.toString('base64url'),ciphertext:out.toString('base64url'),tag:cipher.getAuthTag().toString('base64url')};
 }finally{raw.fill(0);}
}
export function openReceipt(key,scope,p){
 check(Buffer.isBuffer(key)&&key.length===32&&p&&Object.keys(p).length===9&&p.format==='quantic-local-receipt'&&p.version===1&&p.address===scope.address&&p.deviceId===scope.deviceId);
 const aad=metadata(p),iv=bytes(p.iv,12,12),tag=bytes(p.tag,16,16),ciphertext=bytes(p.ciphertext,1,8192);
 let first,last,raw;
 try{
  const d=createDecipheriv('aes-256-gcm',key,iv);d.setAAD(aad);d.setAuthTag(tag);
  first=d.update(ciphertext);last=d.final();raw=Buffer.concat([first,last]);
  const payload=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(raw));check(payloadOK(payload));
  return {id:p.id,digest:p.digest,payload};
 }finally{first?.fill(0);last?.fill(0);raw?.fill(0);}
}
export async function syncReceiptDirectory(path){
 const dir=await open(dirname(path),constants.O_RDONLY|constants.O_DIRECTORY|constants.O_NOFOLLOW);
 try{await dir.sync();}finally{await dir.close();}
}
