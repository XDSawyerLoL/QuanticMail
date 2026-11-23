/**
 * Quantic Scattering: independent V1.4 research transport, not for production.
 * No sockets, handshake, identity or network metadata claims in this module.
 * Every frame is 168 bytes. Version, sequence, data/cover flag and fragment
 * descriptors are authenticated AND encrypted, never passed in clear.
 */
import {randomBytes, createCipheriv, createDecipheriv, hkdfSync} from 'node:crypto';
import {DATA_SHARDS, TOTAL_SHARDS, SHARD_SIZE, encodeShards, recoverShards} from './fec.mjs';

export const FRAME_BYTES=168;
export const HEADER_BYTES=22;
export const MAX_MESSAGE_BYTES=DATA_SHARDS*SHARD_SIZE-2;
const IV_BYTES=12, TAG_BYTES=16, PLAINTEXT_BYTES=FRAME_BYTES-IV_BYTES-TAG_BYTES;
const AAD=Buffer.from('QUANTIC/SCATTERING/RESEARCH-FRAME/V14','utf8');
const MAX_U64=(1n<<64n)-1n;
const MSG_ID_BYTES=8;

function ensureKey(key){if(!Buffer.isBuffer(key)||key.length!==32)throw new RangeError('Session secret must be a Buffer of 32 bytes');}
export function deriveSessionKey(masterSecret, sessionId){
 ensureKey(masterSecret);
 if(!Buffer.isBuffer(sessionId)||sessionId.length!==16)throw new RangeError('Unique authorized session ID must be 16 bytes');
 return Buffer.from(hkdfSync('sha256',masterSecret,sessionId,AAD,32));
}
function uint64(num){if(typeof num!=='bigint'||num<0n||num>MAX_U64)throw new RangeError('64-bit sequence invalid');return num;}
function encodeFrame(key,seq,kind,fragment=null){
 ensureKey(key);uint64(seq);
 if(kind!==0&&kind!==1)throw new RangeError('Invalid kind');
 const p=randomBytes(PLAINTEXT_BYTES);
 p[0]=1;p.writeBigUInt64BE(seq,1);p[9]=kind;
 if(kind===1){
  const {messageId,index,threshold=DATA_SHARDS,total=TOTAL_SHARDS,data}=fragment??{};
  if(!Buffer.isBuffer(messageId)||messageId.length!==MSG_ID_BYTES)throw new RangeError('Message ID must be 8 bytes');
  if(!Number.isInteger(index)||index<0||index>=TOTAL_SHARDS)throw new RangeError('Shard index invalid');
  if(threshold!==DATA_SHARDS||total!==TOTAL_SHARDS)throw new RangeError('Only the 8-of-16 research profile is supported');
  if(!Buffer.isBuffer(data)||data.length!==SHARD_SIZE)throw new RangeError('Shard must be exactly 118 bytes');
  messageId.copy(p,10);p[18]=index;p[19]=threshold;p[20]=total;p[21]=SHARD_SIZE;
  data.copy(p,HEADER_BYTES);
 }
 const iv=randomBytes(IV_BYTES);
 const c=createCipheriv('aes-256-gcm',key,iv,{authTagLength:TAG_BYTES}); c.setAAD(AAD,{plaintextLength:p.length});
 const enc=Buffer.concat([c.update(p),c.final()]);
 return Buffer.concat([iv,enc,c.getAuthTag()]);
}
export class FrameSender {
 constructor({masterSecret,sessionId,initialSequence=0n}={}){
  this.key=deriveSessionKey(masterSecret,sessionId);
  this.sequence=uint64(initialSequence);
 }
 nextCover(){return this.#next(0);}
 nextShard(fragment){return this.#next(1,fragment);}
 #next(kind,fragment){
  if(this.sequence===MAX_U64)throw new Error('Sequence exhausted: rotate the session');
  const packet=encodeFrame(this.key,this.sequence,kind,fragment);
  this.sequence++;
  return packet;
 }
}
export class ReplayWindow {
 constructor(windowSize=2048){
  if(!Number.isInteger(windowSize)||windowSize<16||windowSize>4096)throw new RangeError('Replay window out of range');
  this.windowSize=windowSize;this.max=null;this.bits=0n;this.mask=(1n<<BigInt(windowSize))-1n;
 }
 accept(sequence){
  uint64(sequence);
  if(this.max===null){this.max=sequence;this.bits=1n;return true;}
  if(sequence>this.max){
   const diff=sequence-this.max;
   this.bits=diff>=BigInt(this.windowSize)?1n:((this.bits<<diff)|1n)&this.mask;
   this.max=sequence;return true;
  }
  const distance=this.max-sequence;
  if(distance>=BigInt(this.windowSize))return false;
  const bit=1n<<distance;
  if((this.bits&bit)!==0n)return false;
  this.bits|=bit;return true;
 }
}
export class FrameReceiver {
 constructor({masterSecret,sessionId,replayWindow=2048}={}){
  this.key=deriveSessionKey(masterSecret,sessionId);this.replay=new ReplayWindow(replayWindow);
 }
 accept(packet){
  if(!Buffer.isBuffer(packet)||packet.length!==FRAME_BYTES)return {ok:false,error:'invalid_frame_size'};
  try{
   const iv=packet.subarray(0,IV_BYTES),tag=packet.subarray(FRAME_BYTES-TAG_BYTES),enc=packet.subarray(IV_BYTES,FRAME_BYTES-TAG_BYTES);
   const d=createDecipheriv('aes-256-gcm',this.key,iv,{authTagLength:TAG_BYTES});d.setAAD(AAD,{plaintextLength:enc.length});d.setAuthTag(tag);
   const p=Buffer.concat([d.update(enc),d.final()]);
   if(p[0]!==1||p[9]>1)return {ok:false,error:'invalid_authenticated_header'};
   const sequence=p.readBigUInt64BE(1);
   let shard=null;
   if(p[9]===1){
    if(p[18]>=TOTAL_SHARDS||p[19]!==DATA_SHARDS||p[20]!==TOTAL_SHARDS||p[21]!==SHARD_SIZE)return {ok:false,error:'invalid_authenticated_shard'};
    shard={messageId:Buffer.from(p.subarray(10,18)),index:p[18],data:Buffer.from(p.subarray(HEADER_BYTES))};
   }
   // State mutation occurs ONLY after successful AEAD and header validation.
   if(!this.replay.accept(sequence))return {ok:false,error:'replayed_or_stale'};
   return {ok:true,sequence,kind:p[9]===0?'cover':'data',shard};
  }catch{return {ok:false,error:'authentication_failed'};}
 }
}
export function fragmentMessage(message,messageId=randomBytes(MSG_ID_BYTES)){
 if(!Buffer.isBuffer(message)||message.length>MAX_MESSAGE_BYTES)throw new RangeError(`Message limit is ${MAX_MESSAGE_BYTES} bytes`);
 if(!Buffer.isBuffer(messageId)||messageId.length!==MSG_ID_BYTES)throw new RangeError('Message ID is 8 bytes');
 const full=randomBytes(DATA_SHARDS*SHARD_SIZE);
 full.writeUInt16BE(message.length,0);message.copy(full,2);
 return encodeShards(Array.from({length:DATA_SHARDS},(_,i)=>full.subarray(i*SHARD_SIZE,(i+1)*SHARD_SIZE)))
   .map((data,index)=>({messageId:Buffer.from(messageId),index,threshold:DATA_SHARDS,total:TOTAL_SHARDS,data}));
}
export class MessageCollector {
 constructor({maxPending=128,ttlMs=120000,clock=()=>Date.now()}={}){
  if(!Number.isInteger(maxPending)||maxPending<1||maxPending>4096)throw new RangeError('maxPending invalid');
  this.maxPending=maxPending;this.ttlMs=ttlMs;this.clock=clock;this.pending=new Map();this.completed=new Map();
 }
 add(shard){
  if(!shard||!Buffer.isBuffer(shard.messageId)||shard.messageId.length!==8||!Number.isInteger(shard.index)||shard.index<0||shard.index>=TOTAL_SHARDS||!Buffer.isBuffer(shard.data)||shard.data.length!==SHARD_SIZE)return null;
  const now=this.clock();
  for(const [id,entry] of this.pending)if(now-entry.time>this.ttlMs)this.pending.delete(id);
  for(const [id,when] of this.completed)if(now-when>this.ttlMs)this.completed.delete(id);
  const id=shard.messageId.toString('hex');
  if(this.completed.has(id))return null;
  if(!this.pending.has(id)){
   if(this.pending.size>=this.maxPending)this.pending.delete(this.pending.keys().next().value);
   this.pending.set(id,{time:now,fragments:new Map()});
  }
  const entry=this.pending.get(id);entry.fragments.set(shard.index,shard.data);
  if(entry.fragments.size<DATA_SHARDS)return null;
  const original=recoverShards(entry.fragments);
  if(!original)return null;
  const full=Buffer.concat(original),size=full.readUInt16BE(0);
  this.pending.delete(id);
  if(size>MAX_MESSAGE_BYTES)return null;
  if(this.completed.size>=this.maxPending)this.completed.delete(this.completed.keys().next().value);
  this.completed.set(id,now);
  return {messageId:id,message:Buffer.from(full.subarray(2,2+size))};
 }
}
/** Deterministic slot selection, NOT a cryptographic security primitive. */
export function stratifiedSlots(slots=28,shards=16){
 if(!Number.isInteger(slots)||slots<shards||slots>65535)throw new RangeError('slot budget below shards');
 return Array.from({length:shards},(_,i)=>Math.floor(((i+0.5)*slots)/shards));
}
