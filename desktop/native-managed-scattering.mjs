// One-use native carrier supervisor. No retry, discovery or public HTTP.
import {createHash} from 'node:crypto';
import {spawn} from 'node:child_process';
import {readFile} from 'node:fs/promises';
import {isIPv4} from 'node:net';
import {dirname,isAbsolute} from 'node:path';
import {startNegotiatedScatteringMailboxEndpoint} from '../standalone-relay/native-scattering-negotiated-mailbox-lab.mjs';
import {negotiateUdpSessionLab} from '../lib/quantic/scattering-session-udp-endpoint-lab.mjs';
import {confirmScatteringCutover} from '../lib/quantic/scattering-cutover-lab.mjs';
import {startScatteringMailboxEndpoint} from '../standalone-relay/native-scattering-mailbox.mjs';
const check=x=>{if(!x)throw Error('Managed native carrier refused');};
const pin=/^[a-f0-9]{64}$/;
const exact=(o,keys)=>o&&typeof o==='object'&&!Array.isArray(o)&&Object.keys(o).length===keys.length&&keys.every(k=>Object.hasOwn(o,k));
const port=x=>Number.isInteger(x)&&x>0&&x<=65535;
export function ipv4Endpoint(s){
 check(typeof s==='string'&&s.length<=21);
 const a=s.split(':');check(a.length===2&&isIPv4(a[0])&&Number(a[0].split('.')[0])<224&&Number(a[0].split('.')[0])>0&&port(Number(a[1]))&&String(Number(a[1]))===a[1]);return s;
}
export function validateManagedCarrier(profile,raw,scope,paths){
 check(exact(profile,['configPin','listen','target'])&&pin.test(profile.configPin)&&Buffer.isBuffer(raw)&&raw.length<=16384&&createHash('sha256').update(raw).digest('hex')===profile.configPin);
 ipv4Endpoint(profile.listen);ipv4Endpoint(profile.target);check(profile.listen!==profile.target);
 const c=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(raw));
 check(exact(c,['labOnly','role','secretHex','epochHex','recvPort','httpPort','queueDir','stateDir'])&&c.labOnly===true&&c.role==='client'&&pin.test(c.secretHex)&&pin.test(c.epochHex)&&c.secretHex!==c.epochHex&&!/^0+$/.test(c.secretHex)&&!/^0+$/.test(c.epochHex)&&port(c.recvPort)&&port(c.httpPort)&&c.queueDir===paths.queueDir&&c.stateDir===paths.stateDir);
 check(scope.endpoint==='http://127.0.0.1:'+c.httpPort+'/'&&c.recvPort!==c.httpPort&&!(profile.listen.startsWith('127.0.0.1:')&&Number(profile.listen.split(':')[1])===c.recvPort));
 return c;
}
async function launchNative(binary,args,env){
 const child=spawn(binary,[...args,'-parent-pipe','-duration','30m'],{shell:false,windowsHide:true,cwd:dirname(binary),env,stdio:['pipe','pipe','ignore']});
 let resolveDone,ended=false;const closed=new Promise(r=>{resolveDone=r;});
 const end=()=>{if(!ended){ended=true;resolveDone();}};
 child.once('error',end);child.once('close',end);child.stdin.on('error',()=>child.kill());
 const close=async()=>{if(ended)return;child.stdin.end();const timer=setTimeout(()=>child.kill(),1500);try{await closed;}finally{clearTimeout(timer);}};
 try{
  await new Promise((resolve,reject)=>{
   let buf='';const timeout=setTimeout(()=>finish(Error('Native carrier readiness timeout')),5000);
   const finish=e=>{clearTimeout(timeout);child.stdout.off('data',data);e?reject(e):resolve();};
   const data=b=>{buf+=b.toString('utf8');if(buf==='READY\n'||buf==='READY\r\n')finish();else if(buf.length>7)finish(Error('Invalid readiness'));};
   child.stdout.on('data',data);void closed.then(()=>finish(Error('Native carrier closed before readiness')));
  });
  child.stdout.resume();check(!ended);return {closed,close};
 }catch(e){await close();throw e;}
}
export async function startManagedCarrier({binary,binaryPin,config,listen,target,windowsBootstrap,env},{start=startScatteringMailboxEndpoint,launch=launchNative,read=readFile}={}){
 check(typeof binary==='string'&&isAbsolute(binary)&&pin.test(binaryPin)&&createHash('sha256').update(await read(binary)).digest('hex')===binaryPin);
 ipv4Endpoint(listen);ipv4Endpoint(target);check(listen!==target);
 let endpoint,sink,pacer,stopping=false,resolveClosed;const closed=new Promise(r=>{resolveClosed=r;});
 const close=async()=>{if(stopping)return closed;stopping=true;try{await Promise.allSettled([sink?.close(),pacer?.close()]);}finally{endpoint?.close();resolveClosed();}};
 try{
  endpoint=await start(config,windowsBootstrap?{windowsBootstrap}:{});
  sink=await launch(binary,['-mode','sink','-listen',listen,'-forward','127.0.0.1:'+endpoint.recvPort],env);
  pacer=await launch(binary,['-mode','send','-target',target,'-queue-dir',config.queueDir,'-period-us','5000','-poll','10ms','-wait-mode','native'],env);
  for(const x of [endpoint,sink,pacer])void x.closed.then(close);
  check(!stopping);return Object.freeze({recvPort:endpoint.recvPort,httpPort:endpoint.httpPort,closed,close});
 }catch(e){await close();throw e;}
}

// Explicit negotiated laboratory path; no shared-secret config accepted.
// The dashboard continues using its existing activation profile until native
// signing custody and independently authenticated peer configuration exist.
export async function startNegotiatedManagedCarrier({socket,local,privateKeys,signHandshake,peer,context,timeoutMs=8000,...options}){
 const config=options.config;
 check(config&&!Object.hasOwn(config,'secretHex')&&!Object.hasOwn(config,'epochHex'));
 return startManagedCarrier(options,{start:(c,o)=>startNegotiatedScatteringMailboxEndpoint({config:c,...o,socket,local,privateKeys,signHandshake,peer,context,timeoutMs})});
}

 // Explicit experimental path. Caller owns the connected bootstrap socket
 // and durable fence and must already have stopped the previous carrier.
 // The historical launcher is deliberately unchanged.
export async function startFencedNegotiatedManagedCarrier({socket,local,privateKeys,signHandshake,peer,fence,timeoutMs=8000,cutoverTimeoutMs=5000,...options}){
 const config=options.config;
 check(config?.labOnly===true&&['client','relay'].includes(config.role)&&!Object.hasOwn(config,'secretHex')&&!Object.hasOwn(config,'epochHex'));
 check(fence&&['reserve','stage','finish'].every(k=>typeof fence[k]==='function'));
 const reservation=await fence.reserve(),role=config.role==='client'?'initiator':'responder';
 let material,carrier,endpoint,terminated=false;
 const abort=new AbortController();
 try{
  material=await negotiateUdpSessionLab({socket,role,local,privateKeys,signHandshake,peer,context:reservation.context,timeoutMs});
  await fence.stage(reservation,material);
  carrier=await startManagedCarrier(options,{start:async(c,o)=>{
   const ephemeral={...c,secretHex:material.secret.toString('hex'),epochHex:material.epoch.toString('hex')};
   try{endpoint=await startScatteringMailboxEndpoint(ephemeral,{...o,initiallyPaused:true});return endpoint;}
   finally{delete ephemeral.secretHex;delete ephemeral.epochHex;}
  }});
  void carrier.closed.then(()=>{terminated=true;abort.abort();});
  await confirmScatteringCutover({socket,role,material,context:reservation.context,timeoutMs:cutoverTimeoutMs,signal:abort.signal});
  check(!terminated);
  await fence.finish(reservation,material);
  check(!terminated);endpoint.activate();
  return Object.freeze({...carrier,generation:material.generation,transcript:material.transcript,peerReady:true});
 }catch(e){await carrier?.close();throw e;}
 finally{material?.secret.fill(0);material?.epoch.fill(0);}
}
