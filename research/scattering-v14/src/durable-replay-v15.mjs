/**
 * Quantic Scattering V1.5 research-only durable anti-replay receiver.
 * Every authenticated sequence is committed to disk BEFORE accept() returns it.
 * Compromised storage, rollback from an old snapshot, or machine compromise is
 * outside this lab's guarantees. One writer per state file; no shared network FS.
 */
import {createHmac, hkdfSync, randomBytes, timingSafeEqual} from 'node:crypto';
import {open, readFile, rename, unlink, lstat} from 'node:fs/promises';
import {dirname, basename, join} from 'node:path';
import {FrameReceiver} from './transport.mjs';

const VERSION=1,DOMAIN=Buffer.from('QS-SCATTERING-V15-DURABLE-REPLAY\0');
function checkSecret(masterSecret,sessionId){
 if(!Buffer.isBuffer(masterSecret)||masterSecret.length!==32)throw new Error('Missing 32-byte session master secret');
 if(!Buffer.isBuffer(sessionId)||sessionId.length!==16)throw new Error('Missing 16-byte session identifier');
}
function signKey(masterSecret,sessionId){return Buffer.from(hkdfSync('sha256',masterSecret,sessionId,DOMAIN,32));}
function stableFields(window,sessionId){
 return {version:VERSION,sessionId:sessionId.toString('hex'),windowSize:window.windowSize,
   max:window.max===null?null:window.max.toString(10),bits:window.bits.toString(16)};
}
function protect(key,fields){
 return createHmac('sha256',key).update(JSON.stringify(fields)).digest('hex');
}
async function durableWrite(path,text,{exclusive=false}={}){
 const dir=dirname(path);
 const target=exclusive?path:join(dir,`.${basename(path)}.${randomBytes(12).toString('hex')}.tmp`);
 let fd;
 try{
  fd=await open(target,exclusive?'wx':'wx',0o600);
  await fd.writeFile(text,'utf8');await fd.sync();await fd.close();fd=null;
  if(!exclusive)await rename(target,path);
  // Directory fsync strengthens crash durability on supporting file systems.
  try{const d=await open(dir,'r');try{await d.sync();}finally{await d.close();}}
  catch(e){if(!['EINVAL','ENOTSUP','EISDIR','EBADF','EPERM'].includes(e.code))throw e;}
 }catch(e){if(fd)await fd.close().catch(()=>{});if(!exclusive)await unlink(target).catch(()=>{});throw e;}
}
async function acquire(path){
 const lock=path+'.lock';
 const fd=await open(lock,'wx',0o600);await fd.writeFile('Quantic V1.5 receiver exclusive lock\n');await fd.sync();
 return {fd,path:lock};
}
async function release(lock){
 if(!lock)return;
 try{await lock.fd.close();}finally{await unlink(lock.path).catch(()=>{});}
}
export class DurableFrameReceiver{
 constructor({receiver,masterSecret,sessionId,stateFile,lock}){
  this.receiver=receiver;this.key=signKey(masterSecret,sessionId);this.sessionId=Buffer.from(sessionId);
  this.stateFile=stateFile;this.lock=lock;this.closed=false;this.poisoned=false;this.queue=Promise.resolve();
 }
 static async create({masterSecret,sessionId,stateFile,replayWindow=2048}={}){
  checkSecret(masterSecret,sessionId);
  if(typeof stateFile!=='string'||!stateFile)throw new Error('State file required');
  const lock=await acquire(stateFile);
  const obj=new DurableFrameReceiver({receiver:new FrameReceiver({masterSecret,sessionId,replayWindow}),masterSecret,sessionId,stateFile,lock});
  try{
   await durableWrite(stateFile,obj.serialize(),{exclusive:true});return obj;
  }catch(e){await release(lock);throw e;}
 }
 static async resume({masterSecret,sessionId,stateFile,replayWindow=2048}={}){
  checkSecret(masterSecret,sessionId);
  if(typeof stateFile!=='string'||!stateFile)throw new Error('State file required');
  const lock=await acquire(stateFile);
  try{
   const st=await lstat(stateFile);
   if(!st.isFile()||st.isSymbolicLink()||st.size>20000)throw new Error('Unsafe replay state file');
   const value=JSON.parse(await readFile(stateFile,'utf8'));
   const receiver=new FrameReceiver({masterSecret,sessionId,replayWindow});
   const result=new DurableFrameReceiver({receiver,masterSecret,sessionId,stateFile,lock});
   const {mac,...fields}=value;
   if(typeof mac!=='string'||!/^[0-9a-f]{64}$/.test(mac))throw new Error('Replay state authentication missing');
   const expected=Buffer.from(protect(result.key,fields),'hex');
   if(!timingSafeEqual(expected,Buffer.from(mac,'hex')))throw new Error('Replay state authentication failure');
   if(fields.version!==VERSION||fields.sessionId!==sessionId.toString('hex')||fields.windowSize!==replayWindow)
    throw new Error('Replay state session/profile mismatch');
   if(fields.max!==null&&(!/^(0|[1-9][0-9]*)$/.test(fields.max)||BigInt(fields.max)>(1n<<64n)-1n))throw new Error('Replay state maximum invalid');
   if(typeof fields.bits!=='string'||!/^[0-9a-f]+$/.test(fields.bits))throw new Error('Replay state bitmap invalid');
   const bits=BigInt('0x'+fields.bits),max=fields.max===null?null:BigInt(fields.max);
   if(bits>=1n<<BigInt(replayWindow)||(max===null&&bits!==0n)||(max!==null&&(bits&1n)===0n))throw new Error('Replay state bitmap inconsistent');
   receiver.replay.bits=bits;receiver.replay.max=max;
   return result;
  }catch(e){await release(lock);throw e;}
 }
 serialize(){
  const fields=stableFields(this.receiver.replay,this.sessionId);
  return JSON.stringify({...fields,mac:protect(this.key,fields)})+'\n';
 }
 async accept(packet){
  const op=this.queue.then(async()=>{
   if(this.closed||this.poisoned)return {ok:false,error:'receiver_closed_or_fail_closed'};
   const result=this.receiver.accept(packet);
   if(!result.ok)return result;
   try{await durableWrite(this.stateFile,this.serialize());return result;}
   catch{this.poisoned=true;return {ok:false,error:'durable_commit_failed'};}
  });
  this.queue=op.then(()=>undefined,()=>undefined);
  return op;
 }
 async close(){
  await this.queue;
  this.closed=true;
  const lock=this.lock;this.lock=null;
  this.key.fill(0);
  await release(lock);
 }
}