// Synthetic integration fixture. Two independent native carrier processes
// in each direction, not a public listener, no persistent real identity.
import {createSocket} from 'node:dgram';
import {spawn} from 'node:child_process';
import {randomBytes,createHash} from 'node:crypto';
import {mkdir,realpath} from 'node:fs/promises';
import {join,isAbsolute} from 'node:path';
import {startScatteringMailboxEndpoint} from '../../standalone-relay/native-scattering-mailbox.mjs';
import {openHybridSessionLab} from '../../lib/quantic/scattering-session-lab.mjs';
import {packSession,unpackSession} from '../../lib/quantic/scattering-session-wire-lab.mjs';
import {reliableCellStream} from '../../labs/quantic-native/scattering/scattering-reliable-lab.mjs';
// Explicit lab bootstrap: out-of-band pinned identities and separate
// bootstrap keys. The mailbox data keys are derived, not preprovisioned.
// No claim of automatic discovery or distributed cutover.
async function negotiateCarrier(peers){
 const sockets=[],streams=[],sessions=[],material=[],errors=[];
 const bootstrap=[randomBytes(32),randomBytes(32)];
 try{
  const context={channel:randomBytes(48).toString('hex'),generation:0,previous:'0'.repeat(96)};
  for(let i=0;i<2;i++){
   const sock=createSocket('udp4');sockets.push(sock);
   await new Promise((resolve,reject)=>{sock.once('error',reject);sock.bind(0,'127.0.0.1',resolve);});
   sessions.push(openHybridSessionLab({role:i?'responder':'initiator',...peers[i],peer:peers[1-i].local,context}));
  }
  for(let i=0;i<2;i++){
   const stream=reliableCellStream({sendKey:bootstrap[i],recvKey:bootstrap[1-i],compactPacing:true,dualProofPacing:true,publish:batch=>{
    for(const cell of batch)sockets[i].send(cell,sockets[1-i].address().port,'127.0.0.1',e=>{if(e)errors.push(e);});
    return true;
   }});
   stream.stream.on('error',e=>errors.push(e));streams.push(stream);sockets[i].on('message',b=>stream.receive(b));
  }
  async function carry(i,kind,frame){
   const wire=packSession(kind,frame),src=streams[i].stream,dst=streams[1-i].stream,parts=[];
   let length=0,onData,timer;
   const read=new Promise((resolve,reject)=>{onData=b=>{length+=b.length;if(length>wire.length){reject(Error('handshake frame overflow'));return;}parts.push(b);if(length===wire.length)resolve(Buffer.concat(parts));};dst.on('data',onData);});
   const write=new Promise((resolve,reject)=>src.write(wire,e=>e?reject(e):resolve()));
   try{
    const [got]=await Promise.race([Promise.all([read,write]),new Promise((_,reject)=>{timer=setTimeout(()=>reject(Error('handshake timeout')),5000);})]);
    return unpackSession(kind,got);
   }finally{clearTimeout(timer);dst.off('data',onData);}
  }
  const [a,b]=sessions;
  const hello=await carry(0,'hello',a.begin());
  const response=await carry(1,'response',b.respond(hello));
  b.accept(await carry(0,'finish',a.finish(response)));
  material.push(a.take(),b.take());
  if(errors.length||material[0].transcript!==material[1].transcript||!material[0].secret.equals(material[1].secret)||!material[0].epoch.equals(material[1].epoch))throw Error('session confirmation refused');
  return material.map(m=>({secretHex:m.secret.toString('hex'),epochHex:m.epoch.toString('hex'),transcript:m.transcript}));
 }finally{
  for(const session of sessions)session.close();
  for(const stream of streams)stream.stream.destroy();
  for(const sock of sockets)await new Promise(resolve=>{try{sock.close(resolve);}catch{resolve();}});
  for(const key of bootstrap)key.fill(0);
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
