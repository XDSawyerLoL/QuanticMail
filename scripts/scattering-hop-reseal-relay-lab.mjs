#!/usr/bin/env node
// TRUSTED synthetic-only hop: decrypt and reseal per hop, not an anonymous mixnet.
import {createSocket} from 'node:dgram';
import {mkdir} from 'node:fs/promises';
import {readFileSync,lstatSync} from 'node:fs';
import {isAbsolute} from 'node:path';
import {resealLabHop} from '../lib/quantic/scattering-hop-reseal-lab.mjs';
import {writeSpool} from '../labs/quantic-native/scattering/scattering-cell.mjs';

const [bindA,bindB,queue,secondsRaw,pathA,pathB,pathOut]=process.argv.slice(2);
const check=(ok,msg)=>{if(!ok)throw Error(msg);};
const seconds=Number(secondsRaw);
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
let seq=0;const sockets=[];
try{
 await mkdir(queue,{recursive:true,mode:0o700});
 for(const [idx,bind] of [[0,bindA],[1,bindB]]){
  const [ip,port]=bind.split(':');const sock=createSocket('udp4');
  await new Promise((resolve,reject)=>{sock.once('error',reject);sock.bind(Number(port),ip,resolve);});
  sock.on('message',packet=>{
   if(packet.length!==168||seq>=8192){stats.rejected++;return;}
   let transformed;
   try{transformed=resealLabHop({inputKey:keys[idx],outputKey:keys[2],packet,hopSeq:seq});}
   catch{stats.rejected++;return;}
   if(!transformed){stats.unauthenticated++;return;}
   try{writeSpool(queue,[transformed]);seq++;stats.spooled++;stats[idx?'ingressB':'ingressA']++;}
   catch{stats.spoolErrors++;}
  });
  sockets.push(sock);
 }
 await new Promise(resolve=>setTimeout(resolve,seconds*1000));
 console.log(JSON.stringify({mode:'trusted-hop-reseal-lab',...stats,ciphertextModified:true,
  relayKnowsHopPlaintext:true,notEndToEndAnonymous:true,labOnly:true}));
 check(stats.ingressA>0&&stats.ingressB>0&&stats.spooled===seq&&stats.rejected===0&&stats.spoolErrors===0&&stats.unauthenticated===0,
  're-encryption did not authenticate both synthetic senders');
}finally{for(const sock of sockets)sock.close();for(const key of keys)key.fill(0);}
