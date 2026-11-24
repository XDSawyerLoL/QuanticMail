// Synthetic integration fixture. Two independent native carrier processes
// in each direction, not a public listener, no persistent real identity.
import {createSocket} from 'node:dgram';
import {spawn} from 'node:child_process';
import {randomBytes,createHash} from 'node:crypto';
import {mkdir,realpath} from 'node:fs/promises';
import {join,isAbsolute} from 'node:path';
import {startScatteringMailboxEndpoint} from '../../standalone-relay/native-scattering-mailbox.mjs';
async function freeUDP(){
 const s=createSocket('udp4');
 try{await new Promise((resolve,reject)=>{s.once('error',reject);s.bind(0,'127.0.0.1',resolve);});return s.address().port;}
 finally{await new Promise(r=>s.close(r));}
}
export async function startNativeScatteringLink({dir,binary,relayPort,profile='mailbox',impaired=false}){
 if(process.platform!=='linux'||!isAbsolute(binary)||!Number.isInteger(relayPort)||relayPort<1)throw Error('explicit Linux fixture required');
 const endpoints=[],children=[],proxies=[],timers=new Set(),faultStats=[];
 if(typeof impaired!=='boolean')throw Error('explicit fixture mode required');
 let closing=false;
 async function close(){
  if(closing)return;closing=true;
  for(const e of endpoints)e.close();
  for(const timer of timers)clearTimeout(timer);timers.clear();
  await Promise.all(proxies.map(s=>new Promise(resolve=>{try{s.close(resolve);}catch{resolve();}})));
  await Promise.all(children.map(p=>new Promise(resolve=>{
   if(p.exitCode!==null||p.signalCode!==null)return resolve();
   p.once('close',resolve);p.kill();
  })));
 }
 try{
  await mkdir(dir,{mode:0o700});dir=await realpath(dir);
  const common={labOnly:true,secretHex:randomBytes(32).toString('hex'),epochHex:randomBytes(32).toString('hex'),recvPort:0};
  const queues=[];
  for(const role of ['client','relay']){
   const queueDir=join(dir,role+'-queue'),stateDir=join(dir,role+'-state');
   await mkdir(queueDir,{mode:0o700});await mkdir(stateDir,{mode:0o700});queues.push(queueDir);
   endpoints.push(await startScatteringMailboxEndpoint({...common,role,queueDir,stateDir,httpPort:role==='client'?0:relayPort},{profile}));
  }
  const ports=[await freeUDP(),await freeUDP()];if(ports[0]===ports[1])throw Error('port collision');
  // Faults depend only on packet counters, not authentication, content, or keys.
  // Separate real UDP sockets in each direction. Diagnostic fixture, not a mixnet.
  async function addProxy(target,direction,hop){
   const sock=createSocket('udp4');proxies.push(sock);
   const stats={direction,hop,received:0,forwarded:0,dropped:0,delayed:0,duplicated:0,errors:0};faultStats.push(stats);
   await new Promise((resolve,reject)=>{sock.once('error',reject);sock.bind(0,'127.0.0.1',resolve);});
   sock.on('error',()=>{stats.errors++;void close();});
   function forward(packet){if(closing)return;sock.send(packet,target,'127.0.0.1',e=>{if(e){if(!closing)stats.errors++;}else stats.forwarded++;});}
   sock.on('message',packet=>{
    if(closing)return;
    if(packet.length!==168){stats.errors++;return;}
    const n=++stats.received;
    // Deterministic small loss, delay/reordering and duplicate injection.
    if(n%37===0){stats.dropped++;return;}
    if(n%23===0){stats.delayed++;const timer=setTimeout(()=>{timers.delete(timer);forward(packet);},35);timers.add(timer);return;}
    forward(packet);if(n%53===0){stats.duplicated++;forward(packet);}
   });
   return sock.address().port;
  }
  const launch=args=>{const p=spawn(binary,args,{stdio:'ignore'});children.push(p);p.on('error',()=>{void close();});p.on('exit',()=>{void close();});};
  for(let i=0;i<2;i++){
   launch(['-mode','sink','-listen','127.0.0.1:'+ports[i],'-forward','127.0.0.1:'+endpoints[i].recvPort]);
   let target=ports[1-i];
   if(impaired){target=await addProxy(target,i,2);target=await addProxy(target,i,1);}
   launch(['-target','127.0.0.1:'+target,'-queue-dir',queues[i],'-period-us','5000','-poll','10ms','-wait-mode','native']);
  }
  await new Promise(r=>setTimeout(r,400));if(closing||children.some(p=>p.exitCode!==null||p.signalCode!==null))throw Error('carrier failed');
  return {url:'http://127.0.0.1:'+endpoints[0].httpPort+'/',epochId:createHash('sha256').update(Buffer.from(common.epochHex,'hex')).digest('hex'),faultEvidence:()=>structuredClone(faultStats),close};
 }catch(e){await close();throw e;}
}
