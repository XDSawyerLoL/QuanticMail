// Explicit private-network host service. One independently provisioned
// Scattering epoch per peer. No public HTTP, no secret in arguments, no
// automatic epoch reuse. This is not production session negotiation.
import {createHash} from 'node:crypto';
import {spawn} from 'node:child_process';
import {open,lstat,realpath,readdir} from 'node:fs/promises';
import {isAbsolute,resolve,dirname} from 'node:path';
import {isIPv4} from 'node:net';
import {startScatteringMailboxEndpoint} from './native-scattering-mailbox.mjs';

const check=x=>{if(!x)throw Error('Private Scattering host refused');};
const hex=/^[a-f0-9]{64}$/;
const digest=b=>createHash('sha256').update(b).digest('hex');
const exact=(v,ks)=>v&&Object.getPrototypeOf(v)===Object.prototype&&Object.keys(v).length===ks.length&&ks.every(k=>Object.hasOwn(v,k));
const port=n=>Number.isInteger(n)&&n>=1024&&n<=65535;
const pathOK=p=>typeof p==='string'&&isAbsolute(p)&&resolve(p)===p&&!p.includes('\0');
function privateIPv4(ip){
 if(typeof ip!=='string'||!isIPv4(ip))return false;
 const [a,b]=ip.split('.').map(Number);
 return a===127||a===10||a===172&&b>=16&&b<=31||a===192&&b===168||a===100&&b>=64&&b<=127;
}
export function validatePrivateCarrierPlan(plan){
 check(exact(plan,['format','labOnly','carrier','pacerBinary','pacerSha256','listenIP','listenPort','peerIP','peerPort','periodUs']));
 check(plan.format==='quantic-private-scattering-host/v1'&&plan.labOnly===true&&pathOK(plan.pacerBinary)&&hex.test(plan.pacerSha256));
 check(privateIPv4(plan.listenIP)&&privateIPv4(plan.peerIP)&&port(plan.listenPort)&&port(plan.peerPort));
 const loopback=ip=>ip.startsWith('127.');
 check(loopback(plan.listenIP)===loopback(plan.peerIP));
 check(plan.listenIP!==plan.peerIP||plan.listenPort!==plan.peerPort);
 check(Number.isInteger(plan.periodUs)&&plan.periodUs>=5000&&plan.periodUs<=100000);
 const c=plan.carrier;
 check(exact(c,['labOnly','role','secretHex','epochHex','recvPort','httpPort','queueDir','stateDir']));
 check(c.labOnly===true&&['client','relay'].includes(c.role)&&hex.test(c.secretHex)&&hex.test(c.epochHex)
  &&!/^0+$/.test(c.secretHex)&&!/^0+$/.test(c.epochHex)&&c.secretHex!==c.epochHex);
 check(port(c.recvPort)&&port(c.httpPort)&&c.recvPort!==plan.listenPort&&c.httpPort!==plan.listenPort&&c.httpPort!==c.recvPort);
 check(pathOK(c.queueDir)&&pathOK(c.stateDir)&&c.queueDir!==c.stateDir);
 return plan;
}
async function privateDir(dir){
 check(pathOK(dir)&&await realpath(dir)===dir);
 const st=await lstat(dir);
 check(st.isDirectory()&&st.uid===process.getuid()&&(st.mode&0o077)===0);
}
async function privateFile(path,max){
 check(pathOK(path)&&await realpath(path)===path);
 const f=await open(path,'r');
 try{
  const s=await f.stat();check(s.isFile()&&s.uid===process.getuid()&&(s.mode&0o077)===0&&s.nlink===1&&s.size>0&&s.size<=max);
  const b=Buffer.alloc(s.size+1);let n=0;
  while(n<b.length){const r=await f.read(b,n,b.length-n,null);if(!r.bytesRead)break;n+=r.bytesRead;}
  check(n===s.size);return b.subarray(0,n);
 }finally{await f.close();}
}
export async function loadPrivateCarrierPlan(file,pin){
 check(process.platform==='linux'&&hex.test(pin)&&pathOK(file));
 await privateDir(dirname(file));
 const raw=await privateFile(file,32768);
 try{check(digest(raw)===pin);return validatePrivateCarrierPlan(JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(raw)));}
 finally{raw.fill(0);}
}
async function verifyPacer(plan){
 check(await realpath(plan.pacerBinary)===plan.pacerBinary);
 const s=await lstat(plan.pacerBinary);
 check(s.isFile()&&s.nlink===1&&(s.mode&0o022)===0&&(s.mode&0o111)!==0&&s.size>0&&s.size<=128*1024*1024);
 const f=await open(plan.pacerBinary,'r');
 try{
  const st=await f.stat();check(st.dev===s.dev&&st.ino===s.ino);
  const h=createHash('sha256');for await(const chunk of f.createReadStream({autoClose:false}))h.update(chunk);
  check(h.digest('hex')===plan.pacerSha256);
 }finally{await f.close();}
}
export async function startPrivateCarrierHost(plan,{
 startEndpoint=startScatteringMailboxEndpoint,spawnChild=spawn,verifyBinary=verifyPacer,
 verifyDir=privateDir,inspectQueue=readdir
}={}){
 check(process.platform==='linux');
 validatePrivateCarrierPlan(plan);
 await verifyBinary(plan);
 await verifyDir(plan.carrier.queueDir);await verifyDir(plan.carrier.stateDir);
 check((await inspectQueue(plan.carrier.queueDir)).length===0);
 let endpoint,closing=false,failed=false,resolveClosed;
 const closed=new Promise(r=>{resolveClosed=r;});
 const kids=[];
 async function stop(reason='operator-stop'){
  if(closing)return closed;
  closing=true;failed=reason!=='operator-stop';
  endpoint?.close();
  const exits=kids.map(({child,exit})=>{
   if(child.exitCode===null&&child.signalCode===null){
    try{child.kill('SIGTERM');}catch{}
    const timer=setTimeout(()=>{try{child.kill('SIGKILL');}catch{}},2000);
    return exit.finally(()=>clearTimeout(timer));
   }
   return exit;
  });
  await Promise.all(exits);resolveClosed({reason,failed});
  return closed;
 }
 function start(args){
  const child=spawnChild(plan.pacerBinary,args,{shell:false,stdio:'ignore',env:{PATH:'/usr/bin:/bin',LANG:'C'},cwd:dirname(plan.pacerBinary)});
  let finish;
  const exit=new Promise(r=>{finish=r;});
  kids.push({child,exit});
  child.once('error',()=>{finish();void stop('native-process-error');});
  child.once('close',()=>{finish();void stop('native-process-exit');});
  return new Promise((r,j)=>{
   child.once('spawn',r);child.once('error',j);
  });
 }
 try{
  endpoint=await startEndpoint(plan.carrier);
  void endpoint.closed.then(()=>{if(!closing)void stop('carrier-epoch-closed');});
  await start(['-mode','sink','-listen',plan.listenIP+':'+plan.listenPort,'-forward','127.0.0.1:'+endpoint.recvPort]);
  check(!closing);
  await start(['-target',plan.peerIP+':'+plan.peerPort,'-queue-dir',plan.carrier.queueDir,'-period-us',String(plan.periodUs),'-poll','10ms','-wait-mode','native']);
  await new Promise(r=>setTimeout(r,250));
  check(!closing&&kids.every(({child})=>child.exitCode===null&&child.signalCode===null));
  return Object.freeze({role:plan.carrier.role,httpPort:endpoint.httpPort,recvPort:endpoint.recvPort,
   listenIP:plan.listenIP,listenPort:plan.listenPort,remoteTransportVerified:false,
   closed,close:()=>stop()});
 }catch(e){await stop('startup-failed');throw e;}
}
