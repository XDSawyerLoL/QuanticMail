// Synthetic integration fixture. Two independent native carrier processes
// in each direction, not a public listener, no persistent real identity.
import {createSocket} from 'node:dgram';
import {spawn} from 'node:child_process';
import {randomBytes} from 'node:crypto';
import {mkdir,realpath} from 'node:fs/promises';
import {join,isAbsolute} from 'node:path';
import {startScatteringMailboxEndpoint} from '../../standalone-relay/native-scattering-mailbox.mjs';
async function freeUDP(){
 const s=createSocket('udp4');
 try{await new Promise((resolve,reject)=>{s.once('error',reject);s.bind(0,'127.0.0.1',resolve);});return s.address().port;}
 finally{await new Promise(r=>s.close(r));}
}
export async function startNativeScatteringLink({dir,binary,relayPort}){
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
  const common={labOnly:true,secretHex:randomBytes(32).toString('hex'),epochHex:randomBytes(32).toString('hex'),recvPort:0};
  const queues=[];
  for(const role of ['client','relay']){
   const queueDir=join(dir,role+'-queue'),stateDir=join(dir,role+'-state');
   await mkdir(queueDir,{mode:0o700});await mkdir(stateDir,{mode:0o700});queues.push(queueDir);
   endpoints.push(await startScatteringMailboxEndpoint({...common,role,queueDir,stateDir,httpPort:role==='client'?0:relayPort}));
  }
  const ports=[await freeUDP(),await freeUDP()];if(ports[0]===ports[1])throw Error('port collision');
  const launch=args=>{const p=spawn(binary,args,{stdio:'ignore'});children.push(p);p.on('error',()=>{void close();});p.on('exit',()=>{void close();});};
  for(let i=0;i<2;i++){
   launch(['-mode','sink','-listen','127.0.0.1:'+ports[i],'-forward','127.0.0.1:'+endpoints[i].recvPort]);
   launch(['-target','127.0.0.1:'+ports[1-i],'-queue-dir',queues[i],'-period-us','5000','-poll','10ms','-wait-mode','native']);
  }
  await new Promise(r=>setTimeout(r,400));if(closing||children.some(p=>p.exitCode!==null||p.signalCode!==null))throw Error('carrier failed');
  return {url:'http://127.0.0.1:'+endpoints[0].httpPort+'/',close};
 }catch(e){await close();throw e;}
}
