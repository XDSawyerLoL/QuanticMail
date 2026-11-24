#!/usr/bin/env node
// TRUSTED synthetic-only hop: decrypt and reseal per hop, not an anonymous mixnet.
import {createSocket} from 'node:dgram';
import {mkdir} from 'node:fs/promises';
import {readFileSync,lstatSync} from 'node:fs';
import {isAbsolute} from 'node:path';
import {resealLabHop} from '../lib/quantic/scattering-hop-reseal-lab.mjs';
import {createScatteringBatchMixer} from '../lib/quantic/scattering-batch-mixer-lab.mjs';
import {openReliable} from '../labs/quantic-native/scattering/scattering-reliable-lab.mjs';
import {writeSpool} from '../labs/quantic-native/scattering/scattering-cell.mjs';

const [bindA,bindB,queue,secondsRaw,pathA,pathB,pathOut,mixRaw='0',expectedCoverRaw='0',batchSizeRaw='40',flushRaw='0']=process.argv.slice(2);
const check=(ok,msg)=>{if(!ok)throw Error(msg);};
const seconds=Number(secondsRaw);
check(['0','1'].includes(mixRaw),'unsupported mixing mode');
const mixEnabled=mixRaw==='1';
const batchSize=Number(batchSizeRaw);
check(Number.isSafeInteger(batchSize)&&[8,20,40].includes(batchSize),
 'unsupported lab batch size');
const flushMs=Number(flushRaw);
check([0,200].includes(flushMs)&&(!flushMs||(mixEnabled&&batchSize===8)),'invalid timed flush profile');
const expectedCover=Number(expectedCoverRaw);
check(Number.isSafeInteger(expectedCover)&&[0,80,196].includes(expectedCover),'invalid cover baseline');
check(bindA==='10.252.41.2:49001'&&bindB==='10.252.42.2:49002'&&
 isAbsolute(queue)&&Number.isInteger(seconds)&&seconds>=8&&seconds<=20,
 'explicit isolated trusted-hop lab topology required');
function keyFile(path){check(typeof path==='string'&&isAbsolute(path));
 const s=lstatSync(path);check(s.isFile()&&s.size===32&&(s.mode&0o077)===0,'untrusted key');
 return readFileSync(path);
}
const keys=[keyFile(pathA),keyFile(pathB),keyFile(pathOut)];
check(!keys[0].equals(keys[1])&&!keys[1].equals(keys[2])&&!keys[0].equals(keys[2]),
 'non-independent laboratory keys');
const stats={ingressA:0,ingressB:0,spooled:0,unauthenticated:0,rejected:0,spoolErrors:0};
let seq=0,paddedCover=0,timedFlushes=0,timer=null;const sockets=[];
const mixer=mixEnabled?createScatteringBatchMixer({batchSize,
 onBatch(batch){
  const frames=[];let real=0,pads=0;
  for(const {packet,source} of batch){
   if(source===null){frames.push(packet);pads++;continue;}
   const frame=resealLabHop({inputKey:keys[source],outputKey:keys[2],
     packet,hopSeq:seq+real});
   if(!frame){stats.unauthenticated++;throw Error('untrusted mixed ingress frame');}
   frames.push(frame);real++;
  }
  writeSpool(queue,frames); // one shuffled batch, committed together
  seq+=real;paddedCover+=pads;
  stats.spooled+=real;
  for(const {source} of batch)if(source!==null)stats[source?'ingressB':'ingressA']++;
 }
}):null;
try{
 await mkdir(queue,{recursive:true,mode:0o700});
 for(const [idx,bind] of [[0,bindA],[1,bindB]]){
  const [ip,port]=bind.split(':');const sock=createSocket('udp4');
  await new Promise((resolve,reject)=>{sock.once('error',reject);sock.bind(Number(port),ip,resolve);});
  sock.on('message',packet=>{
   if(packet.length!==168||seq>=8192){stats.rejected++;return;}
   if(mixer){
    // Cover never enters a data batch. A lab test with 20 real cells from B
    // still has 100 on-wire cells because the native source pads with cover.
    const opened=openReliable(keys[idx],packet);
    if(!opened||opened.seq===null||opened.data.length!==92){
     opened?.data?.fill(0);stats.unauthenticated++;return;
    }
    opened.data.fill(0);
    try{mixer.add({packet,source:idx});}
    catch{stats.spoolErrors++;}
    return;
   }
   let transformed;
   try{transformed=resealLabHop({inputKey:keys[idx],outputKey:keys[2],packet,hopSeq:seq});}
   catch{stats.rejected++;return;}
   if(!transformed){stats.unauthenticated++;return;}
   try{writeSpool(queue,[transformed]);seq++;stats.spooled++;stats[idx?'ingressB':'ingressA']++;}
   catch{stats.spoolErrors++;}
  });
  sockets.push(sock);
 }
 // Fixed periodic tick, not triggered by packet arrivals. Native pacer remains constant-rate.
 if(flushMs)timer=setInterval(()=>{
  try{if(mixer.flushPadded())timedFlushes++;}catch{stats.spoolErrors++;clearInterval(timer);}
 },flushMs);
 await new Promise(resolve=>setTimeout(resolve,seconds*1000));
 clearInterval(timer);
 if(mixer){
  try{if(flushMs)mixer.flushPadded();else mixer.drain();}catch{stats.spoolErrors++;}
 }
 console.log(JSON.stringify({mode:'trusted-hop-reseal-lab',...stats,
  mixedBatches:mixEnabled,mixer:mixer?.stats()??null,
  expectedCover,flushMs,paddedCover,timedFlushes,ciphertextModified:true,
  relayKnowsHopPlaintext:true,notEndToEndAnonymous:true,labOnly:true}));
 check(stats.ingressA>0&&stats.ingressB>0&&stats.spooled===seq&&stats.rejected===0&&stats.spoolErrors===0&&stats.unauthenticated===expectedCover,
  're-encryption did not authenticate both synthetic senders');
}finally{clearInterval(timer);for(const sock of sockets)sock.close();for(const key of keys)key.fill(0);}
