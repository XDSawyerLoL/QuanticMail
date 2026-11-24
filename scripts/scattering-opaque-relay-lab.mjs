#!/usr/bin/env node
// Negative-control lab: relays sealed cells BYTE FOR BYTE through native Go pacer.
// Deliberately linkable across hops. Never deploy or use with actual messages.
import {createSocket} from 'node:dgram';
import {mkdir} from 'node:fs/promises';
import {isAbsolute} from 'node:path';
import {writeSpool} from '../labs/quantic-native/scattering/scattering-cell.mjs';

const [a,b,queue,secondsRaw] = process.argv.slice(2);
const check=(ok,msg)=>{if(!ok)throw Error(msg);};
const seconds=Number(secondsRaw);
check(a==='10.252.41.2:49001' && b==='10.252.42.2:49002' &&
 isAbsolute(queue) && Number.isInteger(seconds) && seconds>=8&&seconds<=20,
 'explicit isolated-lab topology required');
const stats={ingressA:0,ingressB:0,spooled:0,rejected:0,spoolErrors:0};
const sockets=[];
try{
 await mkdir(queue,{recursive:true,mode:0o700});
 for(const [idx,bind] of [[0,a],[1,b]]){
  const [ip,port]=bind.split(':');const socket=createSocket('udp4');
  await new Promise((resolve,reject)=>{
   socket.once('error',reject);socket.bind(Number(port),ip,resolve);
  });
  socket.on('message',payload=>{
   if(payload.length!==168){stats.rejected++;return;}
   if(stats.spooled>=2000){stats.rejected++;return;}
   try{writeSpool(queue,[payload]);stats.spooled++;stats[idx?'ingressB':'ingressA']++;}
   catch{stats.spoolErrors++;}
  });
  sockets.push(socket);
 }
 await new Promise(resolve=>setTimeout(resolve,seconds*1000));
 console.log(JSON.stringify({mode:'synthetic-keyless-opaque-relay',...stats,ciphertextModified:false,
  noAnonymityClaim:true,labOnly:true}));
 check(stats.ingressA>0&&stats.ingressB>0&&stats.spoolErrors===0&&stats.rejected===0,
   'relay did not accept both senders cleanly');
}finally{for(const socket of sockets)socket.close();}
