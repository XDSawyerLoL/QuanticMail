#!/usr/bin/env node
// Single-input second-hop diagnostic. No endpoint key is supplied.
import {createSocket} from 'node:dgram';
import {readFileSync,lstatSync} from 'node:fs';
import {isAbsolute} from 'node:path';
import {openReliable} from '../labs/quantic-native/scattering/scattering-reliable-lab.mjs';
import {writeSpool} from '../labs/quantic-native/scattering/scattering-cell.mjs';
import {resealLabHop} from '../lib/quantic/scattering-hop-reseal-lab.mjs';
import {createScatteringBatchMixer} from '../lib/quantic/scattering-batch-mixer-lab.mjs';

const [queue,inPath,outPath,profile='balanced',mixRaw='1']=process.argv.slice(2);
const check=(ok,msg)=>{if(!ok)throw Error(msg)};
check(queue&&isAbsolute(queue)&&['balanced','skewed','sparse'].includes(profile)&&['0','1'].includes(mixRaw),'isolated lab arguments only');
const expected={balanced:200,skewed:120,sparse:4}[profile];
const mix=mixRaw==='1';
check(profile!=='sparse'||mix,'sparse requires padded mixer');
function keyAt(path){
 check(path&&isAbsolute(path),'key path required');
 const st=lstatSync(path);check(st.isFile()&&st.size===32&&(st.mode&0o077)===0,'invalid key file');
 return readFileSync(path);
}
const inputKey=keyAt(inPath),outputKey=keyAt(outPath);
check(!inputKey.equals(outputKey),'independent hop keys required');
const stats={received:0,coverOrInvalid:0,authenticated:0,duplicates:0,invalid:0,spooled:0,paddedCover:0,spoolErrors:0,timedFlushes:0};
const seen=new Set();
let seq=0,timer;
const sock=createSocket('udp4');
function commit(batch){
 const frames=[];let real=0,pads=0;
 for(const {packet,source} of batch){
  if(source===null){frames.push(packet);pads++;continue;}
  const out=resealLabHop({inputKey,outputKey,packet,hopSeq:seq+real});
  check(out!==null,'invalid queued cell');
  frames.push(out);real++;
 }
 writeSpool(queue,frames);
 seq+=real;stats.spooled+=real;stats.paddedCover+=pads;
}
const mixer=mix?createScatteringBatchMixer({batchSize:8,onBatch:commit}):null;
try{
 await new Promise((resolve,reject)=>{sock.once('error',reject);sock.bind(49004,'10.252.44.2',resolve);});
 sock.on('message',packet=>{
  stats.received++;
  if(packet.length!==168){stats.invalid++;return;}
  const opened=openReliable(inputKey,packet);
  if(!opened||opened.seq===null){stats.coverOrInvalid++;return;}
  const n=opened.seq,len=opened.data.length;opened.data.fill(0);
  if(len!==92){stats.invalid++;return;}
  if(seen.has(n)){stats.duplicates++;return;}
  if(seen.size>=expected){stats.invalid++;return;}
  seen.add(n);stats.authenticated++;
  try{
   if(mixer)mixer.add({packet,source:0}); // no original sender label known
   else commit([{packet,source:0}]);
  }catch{stats.spoolErrors++;}
 });
 if(profile==='sparse')timer=setInterval(()=>{
  try{if(mixer.flushPadded())stats.timedFlushes++;}catch{stats.spoolErrors++;clearInterval(timer);}
 },200);
 await new Promise(resolve=>setTimeout(resolve,15000));
 clearInterval(timer);
 if(mixer){try{if(profile==='sparse')mixer.flushPadded();else mixer.drain();}catch{stats.spoolErrors++;}}
 console.log(JSON.stringify({mode:'second-hop-lab',profile,mix,...stats,mixer:mixer?.stats()??null,endpointKeySupplied:false}));
 check(stats.received===550&&stats.coverOrInvalid===550-expected&&stats.authenticated===expected&&
  stats.spooled===expected&&stats.duplicates===0&&stats.invalid===0&&stats.spoolErrors===0,
  'second hop delivery/accounting failed');
}finally{clearInterval(timer);sock.close();inputKey.fill(0);outputKey.fill(0);}
