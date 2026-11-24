// Synthetic integration fixture. Two independent native carrier processes
// in each direction, not a public listener, no persistent real identity.
import {createSocket} from 'node:dgram';
import {spawn} from 'node:child_process';
import {randomBytes,createHash} from 'node:crypto';
import {mkdir,realpath} from 'node:fs/promises';
import {join,isAbsolute} from 'node:path';
import {startScatteringMailboxEndpoint} from '../../standalone-relay/native-scattering-mailbox.mjs';
import {negotiateUdpSessionLab} from '../../lib/quantic/scattering-session-udp-endpoint-lab.mjs';
// Public context and peer pins are provisioned by the fixture. The same
// endpoint-local negotiation engine is used by independent process tests.
async function negotiateCarrier(peers){
 const sockets=[],material=[],errors=[];
 let dropped=0,duplicated=0;
 try{
  const context={channel:randomBytes(48).toString('hex'),generation:0,previous:'0'.repeat(96)};
  for(let i=0;i<2;i++){
   const sock=createSocket('udp4');sockets.push(sock);
   await new Promise((resolve,reject)=>{sock.once('error',reject);sock.bind(0,'127.0.0.1',resolve);});
  }
  const ports=sockets.map(s=>s.address().port);
  for(let i=0;i<2;i++){
   sockets[i].on('error',e=>errors.push(e));
   await new Promise((resolve,reject)=>{sockets[i].once('error',reject);sockets[i].connect(ports[1-i],'127.0.0.1',resolve);});
  }
  // Inject loss and one duplicate at the fixture socket boundary, not in
  // the engine. The engine must retransmit the original signed hello.
  const source=sockets[0];
  const impaired={
   remoteAddress:()=>source.remoteAddress(),
   on:(...args)=>source.on(...args),
   off:(...args)=>source.off(...args),
   send(packet,cb){
    if(packet.subarray(0,4).toString('ascii')==='QHUB'&&packet[5]===1){
     if(!dropped){dropped++;queueMicrotask(()=>cb(null));return;}
     if(!duplicated){duplicated++;source.send(packet,e=>{if(e)errors.push(e);});}
    }
    source.send(packet,cb);
   }
  };
  const negotiate=i=>negotiateUdpSessionLab({socket:i?sockets[1]:impaired,role:i?'responder':'initiator',
   ...peers[i],peer:peers[1-i].local,context,timeoutMs:8000});
  // Keep both sockets alive until both endpoint operations settle.
  const outcomes=await Promise.allSettled([negotiate(1),negotiate(0)]);
  for(const o of outcomes)if(o.status==='fulfilled')material.push(o.value);
  if(outcomes.some(o=>o.status==='rejected'))throw Error('endpoint handshake refused');
  const [b,a]=outcomes.map(o=>o.value);
  if(dropped!==1||duplicated!==1||errors.length||a.transcript!==b.transcript||!a.secret.equals(b.secret)||!a.epoch.equals(b.epoch))throw Error('session confirmation refused');
  return [a,b].map(m=>({secretHex:m.secret.toString('hex'),epochHex:m.epoch.toString('hex'),transcript:m.transcript}));
 }finally{
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
