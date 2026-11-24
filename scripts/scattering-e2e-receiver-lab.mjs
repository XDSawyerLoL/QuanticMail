#!/usr/bin/env node
// Native UDP sink + endpoint E2E inner verifier. Synthetic-only, no user keys.
import {createSocket} from 'node:dgram';
import {spawn} from 'node:child_process';
import {readFileSync,lstatSync} from 'node:fs';
import {isAbsolute} from 'node:path';
import {openReliable} from '../labs/quantic-native/scattering/scattering-reliable-lab.mjs';
import {openEndToEndLab,E2E_LAB} from '../lib/quantic/scattering-e2e-envelope-lab.mjs';

const check=(x,msg)=>{if(!x)throw Error(msg)};
function keyAt(p){
 check(typeof p==='string'&&isAbsolute(p),'absolute key required');
 const st=lstatSync(p);check(st.isFile()&&st.size===32&&(st.mode&0o077)===0,'invalid synthetic key');
 return readFileSync(p);
}
async function main(){
 const [binary,ip,port,durationRaw,outerPath,innerPath]=process.argv.slice(2);
 const duration=Number(durationRaw);
 check(typeof binary==='string'&&isAbsolute(binary)&&ip==='10.252.43.2'&&port==='49003'&&
  Number.isInteger(duration)&&duration>=10&&duration<=20,
  'bounded isolated receiver only');
 const outer=keyAt(outerPath),inner=keyAt(innerPath);
 const local=createSocket('udp4');
 const seen=new Set(),stats={received:0,validLength:0,authenticatedHop:0,authenticatedE2E:0,
  coverOrInvalidHop:0,invalidInner:0,duplicates:0,perSender:{A:0,B:0}};
 try{
  await new Promise((resolve,reject)=>{local.once('error',reject);local.bind(0,'127.0.0.1',resolve);});
  local.on('message',packet=>{
   stats.received++;
   if(packet.length!==168)return;
   stats.validLength++;
   const wrapped=openReliable(outer,packet);
   if(!wrapped||wrapped.seq===null){stats.coverOrInvalidHop++;return;}
   stats.authenticatedHop++;
   if(wrapped.data.length!==E2E_LAB.innerLength){stats.invalidInner++;return;}
   const message=openEndToEndLab(inner,wrapped.data);
   wrapped.data.fill(0);
   if(!message){stats.invalidInner++;return;}
   const id=message.senderId+':'+message.seq;
   if(seen.has(id)){stats.duplicates++;return;}
   seen.add(id);stats.authenticatedE2E++;
   stats.perSender[message.senderId?'B':'A']++;
   message.data.fill(0);
  });
  const report=await new Promise((resolve,reject)=>{
   const args=['-mode','sink','-listen',ip+':'+port,'-forward',
    '127.0.0.1:'+local.address().port,'-duration',duration+'s'];
   const child=spawn(binary,args,{shell:false,windowsHide:true,stdio:['ignore','pipe','pipe']});
   let stdout='',stderr='';
   child.stdout.on('data',d=>stdout=(stdout+d.toString()).slice(-4096));
   child.stderr.on('data',d=>stderr=(stderr+d.toString()).slice(-4096));
   child.once('error',reject);
   child.once('close',code=>code===0?resolve(stdout.trim()):reject(Error('native sink failed '+code+' '+stderr.slice(-500))));
  });
  check(stats.authenticatedE2E>=50&&stats.perSender.A>=20&&stats.perSender.B>=20&&
   stats.duplicates===0&&stats.invalidInner===0,'endpoint verification failed');
  console.log(JSON.stringify({mode:'nested-e2e-synthetic-receive',...stats,
   hopCanDecryptApplicationContent:false,innerKeyNotProvisionedToRelay:true,
   independentPhysicalHost:false,postQuantumClaim:false,realMessageClaim:false,
   sinkReport:report}));
 }finally{outer.fill(0);inner.fill(0);local.close();}
}
main().catch(e=>{console.error('nested receive failed: '+e.message);process.exitCode=1;});
