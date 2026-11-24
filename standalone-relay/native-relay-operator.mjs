// Isolated native laboratory relay operator. Keep old public relay unchanged.
// One process per persistent state directory, separately pinned configuration,
// private mTLS files, no credential generation or remote enrollment here.
import {createHash} from 'node:crypto';
import {open,lstat,realpath,unlink,constants} from 'node:fs/promises';
import {join,dirname,resolve,isAbsolute} from 'node:path';
import {createAttestedPeerSource} from '../desktop/native-attested-peer.mjs';
const fail=()=>{throw Error('Pinned private native relay refused');};
const check=x=>{if(!x)fail();};
const hex=/^[a-f0-9]{64}$/;
const hash=b=>createHash('sha256').update(b).digest('hex');
const pathOK=p=>typeof p==='string'&&isAbsolute(p)&&resolve(p)===p;
const exact=(x,ks)=>x&&Object.getPrototypeOf(x)===Object.prototype&&Object.keys(x).length===ks.length&&ks.every(k=>Object.hasOwn(x,k));
async function privateDirectory(p){
 check(pathOK(p)&&await realpath(p)===p);
 const s=await lstat(p);check(s.isDirectory()&&s.uid===process.getuid()&&(s.mode&0o077)===0);
}
async function privateRead(p,max){
 check(pathOK(p)&&await realpath(p)===p);
 await privateDirectory(dirname(p));
 const f=await open(p,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
 try{
  const s=await f.stat();check(s.isFile()&&s.nlink===1&&s.uid===process.getuid()&&(s.mode&0o077)===0&&s.size>0&&s.size<=max);
  const bytes=Buffer.alloc(s.size+1);let n=0;
  while(n<bytes.length){const r=await f.read(bytes,n,bytes.length-n,null);if(!r.bytesRead)break;n+=r.bytesRead;}
  check(n===s.size);return bytes.subarray(0,n);
 }finally{await f.close();}
}
async function syncDirectory(p){const d=await open(p,constants.O_RDONLY|constants.O_DIRECTORY);try{await d.sync();}finally{await d.close();}}
export async function loadPinnedNativeRelay({file,pin}){
 check(process.platform==='linux'&&pathOK(file)&&hex.test(pin));
 const raw=await privateRead(file,32768);let c;
 try{check(hash(raw)===pin);c=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(raw));}finally{raw.fill(0);}
 check(exact(c,['format','labOnly','dataDir','port','authority','tlsFilePins']));
 check(c.format==='quantic-private-native-relay/v1'&&c.labOnly===true&&pathOK(c.dataDir)&&c.dataDir!==dirname(file));
 check(Number.isInteger(c.port)&&c.port>=1024&&c.port<=65535);
 await privateDirectory(c.dataDir);
 check(exact(c.authority,['authorities','caFile','clientCertFile','clientKeyFile']));
 check(exact(c.tlsFilePins,['caFile','clientCertFile','clientKeyFile']));
 for(const k of ['caFile','clientCertFile','clientKeyFile']){
  const p=c.authority[k];check(pathOK(p)&&dirname(p)===dirname(file)&&hex.test(c.tlsFilePins[k]));
 }
 check(new Set(['caFile','clientCertFile','clientKeyFile'].map(k=>c.authority[k])).size===3);
 const pins=new Map(['caFile','clientCertFile','clientKeyFile'].map(k=>[c.authority[k],c.tlsFilePins[k]]));
 const readTLS=async p=>{
  check(pins.has(p));const b=await privateRead(p,65536);
  if(hash(b)!==pins.get(p)){b.fill(0);fail();}return b;
 };
 return {config:c,readTLS};
}
export async function startPinnedNativeRelay(args,{
 makePeerSource=createAttestedPeerSource,
 startRelay=async opts=>(await import('./server.ts')).startRelayServer(opts)
}={}){
 const {config:c,readTLS}=await loadPinnedNativeRelay(args);
 // Lock even on startup failure. A crash leaves the marker; an operator must
 // reconcile durable state manually before authorizing another start.
 const lock=join(c.dataDir,'.native-relay-active.lock');
 const f=await open(lock,'wx',0o600);
 try{await f.writeFile(JSON.stringify({format:'quantic-native-relay-lock/v1',pid:process.pid,configPin:args.pin}));await f.sync();}finally{await f.close();}
 await syncDirectory(c.dataDir);
 let relay,closed=false;
 async function unlock(){await unlink(lock);await syncDirectory(c.dataDir);}
 try{
  const source=await makePeerSource(c.authority,{read:readTLS});
  relay=await startRelay({host:'127.0.0.1',port:c.port,dataDir:c.dataDir,nativePeerSource:source});
 }catch(e){
  // Do not clear a marker for uncertain partial startup.
  throw e;
 }
 return Object.freeze({port:relay.port,relayId:relay.relayId,close:async()=>{
  if(closed)return;closed=true;
  await relay.close();
  await unlock();
 }});
}
