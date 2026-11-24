// CHUNKED SYNTHETIC LAB v2. Never imports real historical accounts.
// The caller retains the 256-bit encryption key out of band, never on disk.
// Chunk and manifest content are AEAD-authenticated with transaction, role,
// root pin and ordinal. No token, root secret or register modification.
import {createHash,createCipheriv,createDecipheriv,randomBytes} from 'node:crypto';
const refuse=v=>{if(!v)throw Error('Chunked historical restoration laboratory refused');};
const domain='quantic-native-migration-chunk-lab/v2';
const manifestDomain='quantic-native-migration-manifest-lab/v2';
const maxTotal=16*1024*1024;
const blockBytes=81920;
const maxChunks=Math.ceil(maxTotal/blockBytes);
const hex=/^[a-f0-9]{64}$/;
const txRE=/^[a-f0-9]{32}$/;
const names=['messages','contacts','prekeys','outbox'];
const b64=v=>v.toString('base64url');
function from64(value,min,max){
 refuse(typeof value==='string'&&value.length<=Math.ceil(max/3)*4&&/^[A-Za-z0-9_-]+$/.test(value));
 const bytes=Buffer.from(value,'base64url');
 refuse(bytes.length>=min&&bytes.length<=max&&b64(bytes)===value);
 return bytes;
}
function safeJSON(value){
 refuse(value&&Object.getPrototypeOf(value)===Object.prototype&&Object.keys(value).length===4);
 for(const name of names){
  refuse(Array.isArray(value[name])&&value[name].length<=10000);
  const seen=new Set();
  const key=name==='contacts'?'handle':name==='prekeys'?'preKeyId':'id';
  for(const row of value[name]){
   refuse(row&&Object.getPrototypeOf(row)===Object.prototype);
   const id=row[key];
   refuse(typeof id==='string'&&id.length>0&&id.length<=512&&!seen.has(id));
   seen.add(id);
  }
 }
 return value;
}
function params(key,{rootPin,transactionId,role}){
 refuse(Buffer.isBuffer(key)&&key.length===32&&hex.test(rootPin)&&txRE.test(transactionId)&&['s','c'].includes(role));
 return [rootPin,transactionId,role];
}
function meta(rootPin,transactionId,role,kind,index,total){
 return Buffer.from(JSON.stringify([domain,rootPin,transactionId,role,kind,index,total]));
}
function seal(key,info,kind,index,total,raw){
 const [pin,tx,role]=params(key,info);
 refuse(Buffer.isBuffer(raw)&&raw.length>=1&&raw.length<=blockBytes&&total>=1&&total<=maxChunks);
 const aad=meta(pin,tx,role,kind,index,total);
 const iv=randomBytes(12),cipher=createCipheriv('aes-256-gcm',key,iv);
 cipher.setAAD(aad);
 const ciphertext=Buffer.concat([cipher.update(raw),cipher.final()]);
 const envelope={format:domain,version:2,transactionId:tx,role,kind,index,total,iv:b64(iv),ciphertext:b64(ciphertext),tag:b64(cipher.getAuthTag())};
 const out=Buffer.from(JSON.stringify(envelope));
 refuse(out.length<=131072);
 return out;
}
function open(key,info,kind,index,total,packet){
 const [pin,tx,role]=params(key,info);
 refuse(Buffer.isBuffer(packet)&&packet.length<=131072&&packet.length>=100);
 const obj=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(packet));
 refuse(obj&&Object.getPrototypeOf(obj)===Object.prototype&&Object.keys(obj).length===10
  &&obj.format===domain&&obj.version===2&&obj.transactionId===tx
  &&obj.role===role&&obj.kind===kind&&obj.index===index&&obj.total===total);
 // Canonical bytes: reject duplicate fields, whitespace aliases, hidden data.
 refuse(Buffer.from(JSON.stringify(obj)).equals(packet));
 const iv=from64(obj.iv,12,12),ct=from64(obj.ciphertext,1,blockBytes+16),tag=from64(obj.tag,16,16);
 let a,b,raw;
 try{
  const decipher=createDecipheriv('aes-256-gcm',key,iv);
  decipher.setAAD(meta(pin,tx,role,kind,index,total));
  decipher.setAuthTag(tag);
  a=decipher.update(ct);b=decipher.final();raw=Buffer.concat([a,b]);
  refuse(raw.length>=1&&raw.length<=blockBytes);
  return Buffer.from(raw);
 }finally{a?.fill(0);b?.fill(0);raw?.fill(0);}
}
function indexOf(info,raw,total){
 return {format:manifestDomain,version:2,transactionId:info.transactionId,role:info.role,
  plainBytes:raw.length,sha256:createHash('sha256').update(raw).digest('hex'),total};
}
export function migrationChunkFileName(transactionId,role,index){
 refuse(txRE.test(transactionId)&&['s','c'].includes(role)
 &&(index==='manifest'||Number.isSafeInteger(index)&&index>=0&&index<maxChunks));
 return 'm-'+transactionId+'-'+role+'-'+(index==='manifest'?'manifest':String(index).padStart(3,'0'))+'.enc';
}
export function sealChunkedMigrationSnapshot(collections,key,info){
 params(key,info);safeJSON(collections);
 const raw=Buffer.from(JSON.stringify(collections));
 refuse(raw.length>0&&raw.length<=maxTotal);
 try{
  const total=Math.ceil(raw.length/blockBytes);
  const chunks=[];
  for(let i=0;i<total;i++){
   const bytes=raw.subarray(i*blockBytes,Math.min(raw.length,(i+1)*blockBytes));
   chunks.push(seal(key,info,'chunk',i,total,bytes));
  }
  const manifest=seal(key,info,'manifest','manifest',total,Buffer.from(JSON.stringify(indexOf(info,raw,total))));
  return {manifest,chunks,plainBytes:raw.length,transactionId:info.transactionId,role:info.role};
 }finally{raw.fill(0);}
}
export function openChunkedMigrationSnapshot({manifest,chunks},key,info){
 params(key,info);
 refuse(Buffer.isBuffer(manifest)&&Array.isArray(chunks));
 const packet=JSON.parse(manifest.toString('utf8'));
 refuse(packet&&Number.isSafeInteger(packet.total)&&packet.total>=1&&packet.total<=maxChunks);
 const indexText=open(key,info,'manifest','manifest',packet.total,manifest);
 let index;
 try{
  index=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(indexText));
 }finally{indexText.fill(0);}
 refuse(index?.format===manifestDomain&&index.version===2&&index.transactionId===info.transactionId
  &&index.role===info.role&&index.total===packet.total&&hex.test(index.sha256)
  &&Number.isSafeInteger(index.plainBytes)&&index.plainBytes>=1&&index.plainBytes<=maxTotal
  &&Math.ceil(index.plainBytes/blockBytes)===packet.total&&chunks.length===packet.total);
 const portions=[];
 try{
  for(let i=0;i<packet.total;i++)portions.push(open(key,info,'chunk',i,packet.total,chunks[i]));
  const raw=Buffer.concat(portions);
  refuse(raw.length===index.plainBytes&&createHash('sha256').update(raw).digest('hex')===index.sha256);
  try{return safeJSON(JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(raw)));}
  finally{raw.fill(0);}
 }finally{for(const p of portions)p.fill(0);}
}

export function verifyPinnedMigrationManifest(existing,expected,key,info,total){
 const first=open(key,info,'manifest','manifest',total,existing);
 const second=open(key,info,'manifest','manifest',total,expected);
 try{return first.equals(second);}
 finally{first.fill(0);second.fill(0);}
}
export const MIGRATION_CHUNK_LAB_LIMITS=Object.freeze({maxPlainBytes:maxTotal,chunkBytes:blockBytes,maxChunks});
