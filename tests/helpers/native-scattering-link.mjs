// Synthetic integration fixture. Two independent native carrier processes
// in each direction, not a public listener, no persistent real identity.
import {createSocket} from 'node:dgram';
import {spawn} from 'node:child_process';
import {randomBytes,createHash} from 'node:crypto';
import {mkdir,realpath} from 'node:fs/promises';
import {join,isAbsolute} from 'node:path';
import {startScatteringMailboxEndpoint} from '../../standalone-relay/native-scattering-mailbox.mjs';
import {openHybridSessionLab} from '../../lib/quantic/scattering-session-lab.mjs';
import {fragmentSession,openSessionAssembly} from '../../lib/quantic/scattering-session-udp-bootstrap-lab.mjs';
// Public context and peer pins are preconfigured, no shared bootstrap key.
// Only this fixture orchestrates cutover. Bootstrap traffic is recognizable.
async function negotiateCarrier(peers){
 const sockets=[],sessions=[],material=[],errors=[];
 let dropped=0;
 try{
  const context={channel:randomBytes(48).toString('hex'),generation:0,previous:'0'.repeat(96)};
  for(let i=0;i<2;i++){
   const sock=createSocket('udp4');sockets.push(sock);
   await new Promise((resolve,reject)=>{sock.once('error',reject);sock.bind(0,'127.0.0.1',resolve);});
   sessions.push(openHybridSessionLab({role:i?'responder':'initiator',...peers[i],peer:peers[1-i].local,context}));
  }
  const ports=sockets.map(s=>s.address().port);
  for(let i=0;i<2;i++){
   sockets[i].on('error',e=>errors.push(e));
   await new Promise(resolve=>sockets[i].connect(ports[1-i],'127.0.0.1',resolve));
  }
  async function carry(i,kind,frame){
   const packets=fragmentSession(kind,frame,context),dst=sockets[1-i],src=sockets[i],assembly=openSessionAssembly(kind,context);
   let timer,retry,onMessage,attempt=0;
   try{return await new Promise((resolve,reject)=>{
    onMessage=packet=>{try{const result=assembly.push(packet);if(result)resolve(result);}catch(e){reject(e);}};
    dst.on('message',onMessage);
    const send=()=>{
     if(++attempt>20){reject(Error('bootstrap retry limit'));return;}
     // Deliberately lose one hello fragment; reorder the rest and send
     // an exact duplicate. Repeat identical bytes, never regenerate keys.
     const batch=[...packets].reverse();
     if(kind==='hello'&&attempt===1){batch.pop();dropped++;}
     if(batch.length>1)batch.push(batch[0]);
     for(const packet of batch)src.send(packet,e=>{if(e)reject(e);});
    };
    timer=setTimeout(()=>reject(Error('bootstrap timeout')),4000);
    retry=setInterval(send,150);send();
   });}finally{clearInterval(retry);clearTimeout(timer);dst.off('message',onMessage);}
  }
  const [a,b]=sessions;
  const hello=await carry(0,'hello',a.begin());
  const response=await carry(1,'response',b.respond(hello));
  b.accept(await carry(0,'finish',a.finish(response)));
  material.push(a.take(),b.take());
  if(dropped!==1||errors.length||material[0].transcript!==material[1].transcript||!material[0].secret.equals(material[1].secret)||!material[0].epoch.equals(material[1].epoch))throw Error('session confirmation refused');
  return material.map(m=>({secretHex:m.secret.toString('hex'),epochHex:m.epoch.toString('hex'),transcript:m.transcript}));
 }finally{
  for(const session of sessions)session.close();
  for(const sock of sockets)await new Promise(resolve=>{try{sock.close(resolve);}catch{resolve();}});
  for(const m of material){m.secret.fill(0);m.epoch.fill(0);}
 }
}
async function freeUDP(){
 const s=createSocket('udp4');
 try{await new Promise((resolve,reject)=>{s.once('error',reject);s.bind(0,'127.0.0.1',resolve);});return s.address().port;}
 finally{await new Promise(r=>s.close(r));}
}
export async function startNativeScatteringLink({dir,binary,relayPort,profile='mailbox',sessionPeers}){
 if(process.platform!=='linux'||!isAbsolute(binary)||!Number.isInteger(relayPort)||relayPort<1)throw Error('explicit Linux fixture required');
 const endpoints=[],children=[];
 let closing=false;
 async function close(){
  if(closing)return;closing=true;
  for(const e of endpoints)e.close();
  await Promise.all(children.map(p=>new Promise(resolve=>{
   if(p.exitCode!==null||p.signalCode!==null)return resolve();
   p.once('close',resolve);p.kill();
  })));
 }
 try{
  await mkdir(dir,{mode:0o700});dir=await realpath(dir);
  const negotiated=sessionPeers?await negotiateCarrier(sessionPeers):null;
  const common={labOnly:true,...(negotiated?{}:{secretHex:randomBytes(32).toString('hex'),epochHex:randomBytes(32).toString('hex')}),recvPort:0};
  const queues=[];
  for(const role of ['client','relay']){
   const queueDir=join(dir,role+'-queue'),stateDir=join(dir,role+'-state');
   await mkdir(queueDir,{mode:0o700});await mkdir(stateDir,{mode:0o700});queues.push(queueDir);
   endpoints.push(await startScatteringMailboxEndpoint({...common,...(negotiated?negotiated[role==='client'?0:1]:{}),role,queueDir,stateDir,httpPort:role==='client'?0:relayPort},{profile}));
  }
  const ports=[await freeUDP(),await freeUDP()];if(ports[0]===ports[1])throw Error('port collision');
  const launch=args=>{const p=spawn(binary,args,{stdio:'ignore'});children.push(p);p.on('error',()=>{void close();});p.on('exit',()=>{void close();});};
  for(let i=0;i<2;i++){
   launch(['-mode','sink','-listen','127.0.0.1:'+ports[i],'-forward','127.0.0.1:'+endpoints[i].recvPort]);
   launch(['-target','127.0.0.1:'+ports[1-i],'-queue-dir',queues[i],'-period-us','5000','-poll','10ms','-wait-mode','native']);
  }
  await new Promise(r=>setTimeout(r,400));if(closing||children.some(p=>p.exitCode!==null||p.signalCode!==null))throw Error('carrier failed');
  return {url:'http://127.0.0.1:'+endpoints[0].httpPort+'/',epochId:createHash('sha256').update(Buffer.from(negotiated?negotiated[0].epochHex:common.epochHex,'hex')).digest('hex'),negotiated:!!negotiated,close};
 }catch(e){await close();throw e;}
}
