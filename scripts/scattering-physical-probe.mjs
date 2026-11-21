// Bounded synthetic reachability probe. No keys, account data or user traffic.
// Receives only via the real native sink; never reflects traffic to peers.
import {createSocket} from 'node:dgram';
import {spawn} from 'node:child_process';
import {mkdtemp,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,isAbsolute} from 'node:path';
import {isIPv4} from 'node:net';
import {performance} from 'node:perf_hooks';
const check=(x)=>{if(!x)throw Error('Scattering probe refused');};
const wait=ms=>new Promise(r=>setTimeout(r,ms));
const number=(s,min,max)=>{const n=Number(s);check(Number.isInteger(n)&&n>=min&&n<=max);return n;};
const port=s=>number(s,1024,65535);
function child(binary,args){
 const p=spawn(binary,args,{shell:false,windowsHide:true,stdio:['ignore','pipe','pipe']});
 let data='',err='';
 p.stdout.on('data',b=>{if(data.length<4096)data+=b.toString();});
 p.stderr.on('data',b=>{if(err.length<4096)err+=b.toString();});
 const done=new Promise(resolve=>{p.once('error',()=>resolve({ok:false,data:'',err:'launch failed'}));p.once('close',code=>resolve({ok:code===0,data,err}));});
 return {p,done};
}
async function listenLocal(){
 const socket=createSocket('udp4');
 await new Promise((resolve,reject)=>{socket.once('error',reject);socket.bind(0,'127.0.0.1',resolve);});
 const times=[];let malformed=0,overflow=0;
 socket.on('message',b=>{if(b.length!==168){malformed++;return;}if(times.length<20000)times.push(performance.now());else overflow++;});
 return {socket,times,stats(){const gaps=times.slice(1).map((x,i)=>x-times[i]).sort((a,b)=>a-b);return {received:times.length,malformed,overflow,gapMedianMs:gaps.length?gaps[Math.floor(gaps.length/2)]:null,gapP95Ms:gaps.length?gaps[Math.floor((gaps.length-1)*.95)]:null,gapMaxMs:gaps.at(-1)??null};}};
}
async function freePort(){const s=createSocket('udp4');await new Promise((r,j)=>{s.once('error',j);s.bind(0,'127.0.0.1',r);});const p=s.address().port;await new Promise(r=>s.close(r));return p;}
async function sink(binary,ip,p,seconds,local){
 const n=child(binary,['-mode','sink','-listen',ip+':'+p,'-forward','127.0.0.1:'+local.socket.address().port,'-duration',seconds+'s']);
 return n;
}
async function send(binary,ip,p,seconds){
 const dir=await mkdtemp(join(tmpdir(),'qs-cover-probe-'));
 const n=child(binary,['-target',ip+':'+p,'-queue-dir',dir,'-period-us','20000','-poll','10ms','-wait-mode','native','-duration',seconds+'s']);
 try{const r=await n.done;check(r.ok);return r.data.trim();}finally{n.p.kill();await rm(dir,{recursive:true,force:true});}
}
async function main(){
 const [mode,binary,...args]=process.argv.slice(2);
 check(isAbsolute(binary));
 if(mode==='send'){
  check(args.length===3&&isIPv4(args[0])&&args[0]!=='0.0.0.0'&&!args[0].startsWith('127.')&&!args[0].startsWith('224.')&&!args[0].startsWith('255.'));
  const p=port(args[1]),seconds=number(args[2],5,120);
  console.log(JSON.stringify({mode:'physical-cover-send',report:await send(binary,args[0],p,seconds),wireDeliveryProven:false}));
 }else if(mode==='receive'){
  check(args.length===3&&isIPv4(args[0])&&args[0]!=='0.0.0.0');
  const p=port(args[1]),seconds=number(args[2],10,150),local=await listenLocal();
  let n;
  try{n=await sink(binary,args[0],p,seconds,local);console.log('Receiver started; start the sender on the other authorized machine.');const r=await n.done;check(r.ok);const stats=local.stats();console.log(JSON.stringify({mode:'physical-cover-receive',...stats,sinkReport:r.data.trim(),authenticatedPayloadProven:false,indistinguishabilityProven:false}));check(stats.received>0);}
  finally{n?.p.kill();local.socket.close();}
 }else if(mode==='loopback'){
  check(args.length===1);const seconds=number(args[0],5,30);
  const p=await freePort(),local=await listenLocal();let n;
  try{n=await sink(binary,'127.0.0.1',p,seconds+3,local);await wait(400);const sent=await send(binary,'127.0.0.1',p,seconds);const r=await n.done;check(r.ok);const stats=local.stats();console.log(JSON.stringify({mode:'loopback-only',sent,sinkReport:r.data.trim(),...stats,physicalNetworkProven:false}));check(stats.received>0&&stats.malformed===0&&stats.overflow===0);}
  finally{n?.p.kill();local.socket.close();}
 }else throw Error('invalid probe mode');
}
main().catch(()=>{console.error('Scattering cover probe refused or no packets received.');process.exitCode=1;});
