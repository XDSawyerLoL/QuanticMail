// Bounded synthetic reachability probe. No keys, account data or user traffic.
// Receives only via the real native sink; never reflects traffic to peers.
import {createSocket} from 'node:dgram';
import {randomBytes} from 'node:crypto';
import {readFileSync,lstatSync} from 'node:fs';
import {sealReliable,openReliable} from '../labs/quantic-native/scattering/scattering-reliable-lab.mjs';
import {writeSpool} from '../labs/quantic-native/scattering/scattering-cell.mjs';
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
function readTestKey(path){
 check(typeof path==='string'&&isAbsolute(path));
 const stat=lstatSync(path);
 check(stat.isFile()&&stat.size===32&&(stat.mode&0o077)===0);
 return readFileSync(path);
}
function child(binary,args){
 const p=spawn(binary,args,{shell:false,windowsHide:true,stdio:['ignore','pipe','pipe']});
 let data='',err='';
 p.stdout.on('data',b=>{if(data.length<4096)data+=b.toString();});
 p.stderr.on('data',b=>{if(err.length<4096)err+=b.toString();});
 const done=new Promise(resolve=>{p.once('error',()=>resolve({ok:false,data:'',err:'launch failed'}));p.once('close',code=>resolve({ok:code===0,data,err}));});
 return {p,done};
}
async function listenLocal(authKey=null){
 const socket=createSocket('udp4');
 await new Promise((resolve,reject)=>{socket.once('error',reject);socket.bind(0,'127.0.0.1',resolve);});
 const times=[];let malformed=0,overflow=0,authenticatedSynthetic=0,unauthenticated=0,replays=0;
 const seen=new Set();
 socket.on('message',b=>{
  if(b.length!==168){malformed++;return;}
  if(times.length<20000)times.push(performance.now());else {overflow++;return;}
  if(authKey){
   const frame=openReliable(authKey,b);
   if(!frame||frame.seq===null){unauthenticated++;return;}
   if(seen.has(frame.seq)){replays++;return;}
   seen.add(frame.seq);
   authenticatedSynthetic++;
  }
 });
 return {socket,times,stats(){const gaps=times.slice(1).map((x,i)=>x-times[i]).sort((a,b)=>a-b);return {received:times.length,malformed,overflow,
  authenticatedSynthetic,unauthenticated,replays,
  gapMedianMs:gaps.length?gaps[Math.floor(gaps.length/2)]:null,
  gapP95Ms:gaps.length?gaps[Math.floor((gaps.length-1)*.95)]:null,
  gapMaxMs:gaps.at(-1)??null};}};
}
async function freePort(){const s=createSocket('udp4');await new Promise((r,j)=>{s.once('error',j);s.bind(0,'127.0.0.1',r);});const p=s.address().port;await new Promise(r=>s.close(r));return p;}
async function sink(binary,ip,p,seconds,local){
 const n=child(binary,['-mode','sink','-listen',ip+':'+p,'-forward','127.0.0.1:'+local.socket.address().port,'-duration',seconds+'s']);
 return n;
}
async function send(binary,ip,p,seconds,synthetic=false,keyPath=null){
 const dir=await mkdtemp(join(tmpdir(),'qs-cover-probe-'));
 if(synthetic){
  // Native transport remains keyless. Only bounded synthetic AES-GCM cells enter its local queue.
  const key=keyPath?readTestKey(keyPath):randomBytes(32), cells=[];
  try{
   for(let seq=0;seq<seconds*50+40;seq++)
    cells.push(sealReliable(key,{seq,ack:0,data:randomBytes(128)}));
   writeSpool(dir,cells);
  }catch(e){await rm(dir,{recursive:true,force:true});throw e;}
  finally{key.fill(0);}
 }
 const n=child(binary,['-target',ip+':'+p,'-queue-dir',dir,'-period-us','20000','-poll','10ms','-wait-mode','native','-duration',seconds+'s']);
 try{const r=await n.done;check(r.ok);return r.data.trim();}finally{n.p.kill();await rm(dir,{recursive:true,force:true});}
}
async function main(){
 const [mode,binary,...args]=process.argv.slice(2);
 check(isAbsolute(binary));
 if(mode==='send'||mode==='send-synthetic'){
  check((args.length===3||(mode==='send-synthetic'&&args.length===4))&&isIPv4(args[0])&&args[0]!=='0.0.0.0'&&!args[0].startsWith('127.')&&!args[0].startsWith('224.')&&!args[0].startsWith('255.'));
  if(args.length===4)check(isAbsolute(args[3]));
  const p=port(args[1]),seconds=number(args[2],5,120);
  console.log(JSON.stringify({mode:mode==='send-synthetic'?'physical-synthetic-send':'physical-cover-send',report:await send(binary,args[0],p,seconds,mode==='send-synthetic',args[3]??null),wireDeliveryProven:false,authenticatedPayloadProven:false}));
 }else if(mode==='receive'||mode==='receive-synthetic'){
  check(args.length===(mode==='receive-synthetic'?4:3)&&isIPv4(args[0])&&args[0]!=='0.0.0.0');
  const p=port(args[1]),seconds=number(args[2],10,150);
  const key=mode==='receive-synthetic'?readTestKey(args[3]):null;
  const local=await listenLocal(key);
  let n;
  try{n=await sink(binary,args[0],p,seconds,local);console.log('Receiver started; start the sender on the other authorized machine.');const r=await n.done;check(r.ok);const stats=local.stats();console.log(JSON.stringify({mode:mode==='receive-synthetic'?'physical-synthetic-receive':'physical-cover-receive',...stats,sinkReport:r.data.trim(),authenticatedPayloadProven:mode==='receive-synthetic'&&stats.authenticatedSynthetic>0,indistinguishabilityProven:false}));check(stats.received>0&&(mode!=='receive-synthetic'||(stats.authenticatedSynthetic>0&&stats.replays===0)));}
  finally{n?.p.kill();local.socket.close();}
 }else if(mode==='loopback'){
  check(args.length===1);const seconds=number(args[0],5,30);
  const p=await freePort(),local=await listenLocal();let n;
  try{n=await sink(binary,'127.0.0.1',p,seconds+3,local);await wait(400);const sent=await send(binary,'127.0.0.1',p,seconds);const r=await n.done;check(r.ok);const stats=local.stats();console.log(JSON.stringify({mode:'loopback-only',sent,sinkReport:r.data.trim(),...stats,physicalNetworkProven:false}));check(stats.received>0&&stats.malformed===0&&stats.overflow===0);}
  finally{n?.p.kill();local.socket.close();}
 }else throw Error('invalid probe mode');
}
main().catch(()=>{console.error('Scattering cover probe refused or no packets received.');process.exitCode=1;});
