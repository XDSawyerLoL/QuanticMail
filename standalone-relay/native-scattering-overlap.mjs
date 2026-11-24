// Fixed make-before-break laboratory schedule. Two independent epochs may
// overlap; stable loopback ingress assigns each operation exactly once.
import {createServer,request} from 'node:http';
import {isAbsolute,resolve} from 'node:path';
import {performance} from 'node:perf_hooks';
import {setTimeout as sleep} from 'node:timers/promises';
import {validatePrivateCarrierPlan,startPrivateCarrierHost} from './native-scattering-host.mjs';
const check=x=>{if(!x)throw Error('Overlapping Scattering schedule refused');};
const exact=(v,ks)=>v&&Object.getPrototypeOf(v)===Object.prototype&&Object.keys(v).length===ks.length&&ks.every(k=>Object.hasOwn(v,k));
const hex=/^[a-f0-9]{64}$/;
const port=x=>Number.isInteger(x)&&x>=1024&&x<=65535;
const pathOK=p=>typeof p==='string'&&isAbsolute(p)&&resolve(p)===p;
export const OVERLAP_POLICY=Object.freeze({overlapMs:40000,warmupMs:5000,drainMs:35000,minSlotMs:85000,maxSlotMs:3600000,maxSlots:24});
const P=OVERLAP_POLICY,MAX=32768,BASE='/api/quantic/native/v1/';
const allowed=new Set(['send','pull','ack','recover']);
const errorBody=Buffer.from('{"error":"native mailbox operation not confirmed"}');
export function validateOverlapSchedule(spec,plans,{now=Date.now()}={}){
 check(exact(spec,['format','labOnly','gatewayPort','slots'])&&spec.format==='quantic-private-scattering-overlap/v1'&&spec.labOnly===true);
 check(Array.isArray(spec.slots)&&spec.slots.length>=2&&spec.slots.length<=P.maxSlots&&Array.isArray(plans)&&plans.length===spec.slots.length);
 const first=plans[0];validatePrivateCarrierPlan(first);
 const client=first.carrier.role==='client';
 check(client?port(spec.gatewayPort):spec.gatewayPort===null);
 const keys=new Set(),queues=new Set(),files=new Set(),ports=new Set(client?[spec.gatewayPort]:[first.carrier.httpPort]),peerPorts=new Set();
 for(let i=0;i<plans.length;i++){
  const s=spec.slots[i],p=plans[i];validatePrivateCarrierPlan(p);
  check(exact(s,['startMs','endMs','file','pin'])&&pathOK(s.file)&&hex.test(s.pin)&&!files.has(s.file));files.add(s.file);
  check(Number.isSafeInteger(s.startMs)&&Number.isSafeInteger(s.endMs)&&s.startMs>=now+500&&s.endMs<=now+86400000
   &&s.endMs-s.startMs>=P.minSlotMs&&s.endMs-s.startMs<=P.maxSlotMs);
  if(i)check(s.startMs===spec.slots[i-1].endMs-P.overlapMs);
  check(['pacerBinary','pacerSha256','listenIP','peerIP','periodUs'].every(k=>p[k]===first[k]));
  check(p.carrier.role===first.carrier.role&&p.carrier.stateDir===first.carrier.stateDir&&(!client?p.carrier.httpPort===first.carrier.httpPort:true));
  check(!queues.has(p.carrier.queueDir)&&p.carrier.queueDir!==first.carrier.stateDir);queues.add(p.carrier.queueDir);
  for(const key of [p.carrier.secretHex,p.carrier.epochHex]){check(!keys.has(key));keys.add(key);}
  for(const n of [p.listenPort,p.carrier.recvPort,...(client?[p.carrier.httpPort]:[])]){check(!ports.has(n));ports.add(n);}
  check(!peerPorts.has(p.peerPort));peerPorts.add(p.peerPort);
 }
 return true;
}
function answer(res,status,b=errorBody){
 if(res.destroyed||res.writableEnded)return;
 res.writeHead(status,{'Content-Type':'application/json','Content-Length':b.length,'Cache-Control':'no-store','Connection':'close'});res.end(b);
}
async function readBounded(stream,length){
 const parts=[];let n=0;
 for await(const part of stream){n+=part.length;check(n<=MAX&&n<=length);parts.push(part);}
 check(n===length);return Buffer.concat(parts,n);
}
export async function startStableMailboxGateway({port:listenPort,select,signal}){
 check(port(listenPort)&&typeof select==='function');
 let busy=false,closed=false,upstream;
 function forward(lane,op,auth,body){
  return new Promise((resolve,reject)=>{
   const q=request({hostname:'127.0.0.1',port:lane.httpPort,path:BASE+op,method:'POST',agent:false,
    headers:{'Content-Type':'application/json','Content-Length':body.length,Authorization:auth,Connection:'close'}},async res=>{
     try{
      const len=Number(res.headers['content-length']);
      check(!res.headers['transfer-encoding']&&Number.isInteger(len)&&len>=1&&len<=MAX&&Number.isInteger(res.statusCode)&&res.statusCode>=200&&res.statusCode<=599);
      resolve({status:res.statusCode,body:await readBounded(res,len)});
     }catch(e){res.destroy();reject(e);}
    });
   upstream=q;const timer=setTimeout(()=>q.destroy(Error('lane deadline')),22000);
   q.on('error',reject);q.on('close',()=>{clearTimeout(timer);if(upstream===q)upstream=undefined;});q.end(body);
  });
 }
 const server=createServer(async(req,res)=>{
  const op=req.url?.startsWith(BASE)?req.url.slice(BASE.length):'',auth=req.headers.authorization,len=Number(req.headers['content-length']);
  if(req.method!=='POST'||!allowed.has(op)||typeof auth!=='string'||!/^Bearer [A-Za-z0-9._~-]{40,256}$/.test(auth)||req.headers.origin!==undefined||req.headers['transfer-encoding']!==undefined||req.headers['content-type']!=='application/json'||!Number.isInteger(len)||len<1||len>MAX){answer(res,400);req.resume();return;}
  if(closed||busy||!select()){answer(res,503);req.resume();return;}
  busy=true;let body;
  const readTimer=setTimeout(()=>req.destroy(Error('ingress deadline')),5000);
  try{
   body=await readBounded(req,len);clearTimeout(readTimer);
   const lane=select();
   if(!lane){answer(res,503);return;}
   // Capture this lane ONCE. An error or timeout cannot route the request
   // into another epoch, even if the schedule has advanced.
   check(port(lane.httpPort)&&lane.httpPort!==listenPort);
   const r=await forward(lane,op,auth,body);answer(res,r.status,r.body);
  }catch{answer(res,502);}
  finally{clearTimeout(readTimer);body?.fill(0);busy=false;}
 });
 server.maxConnections=8;server.requestTimeout=10000;server.headersTimeout=5000;
 server.setTimeout(30000,s=>s.destroy());
 await new Promise((r,j)=>{server.once('error',j);server.listen(listenPort,'127.0.0.1',()=>{server.removeListener('error',j);r();});});
 const close=async()=>{
  if(closed)return;closed=true;upstream?.destroy();
  await new Promise(r=>{server.close(r);server.closeAllConnections();});
 };
 signal?.addEventListener('abort',()=>{void close();},{once:true});
 return {port:listenPort,close};
}
export async function runOverlapSchedule({spec,plans},{
 signal,onSlot=()=>{},startHost=startPrivateCarrierHost,startGateway=startStableMailboxGateway,
 now=Date.now,monotonic=()=>performance.now(),
 pause=async(ms,s)=>sleep(ms,undefined,{signal:s})
}={}){
 validateOverlapSchedule(spec,plans,{now:now()});
 const baseWall=now(),baseMono=monotonic();
 const abort=new AbortController(),hosts=new Map(),expectedClose=new Set();
 let selected=null,gateway,finished=0,fault=false;
 const stop=()=>abort.abort();signal?.addEventListener('abort',stop,{once:true});
 if(signal?.aborted)stop();
 function clock(){check(Math.abs((now()-baseWall)-(monotonic()-baseMono))<=1000);}
 async function waitUntil(at){
  while(now()<at){check(!abort.signal.aborted);clock();await pause(Math.min(200,at-now()),abort.signal);}
  clock();check(!abort.signal.aborted&&now()-at<=1000);
 }
 const events=[];
 for(let i=0;i<plans.length;i++){
  const s=spec.slots[i];
  events.push({at:s.startMs,kind:'start',i},{at:s.startMs+P.warmupMs,kind:'select',i},{at:s.endMs,kind:'close',i});
 }
 events.push({at:spec.slots.at(-1).endMs-P.drainMs,kind:'drain',i:plans.length-1});
 events.sort((a,b)=>a.at-b.at);
 const active=()=>selected!==null&&!abort.signal.aborted?hosts.get(selected):null;
 try{
  if(plans[0].carrier.role==='client')gateway=await startGateway({port:spec.gatewayPort,select:active,signal:abort.signal});
  for(const e of events){
   await waitUntil(e.at);
   const slot=spec.slots[e.i];
   if(e.kind==='start'){
    // Relay keeps the old epoch available during drain for in-flight work.
    // Client gateway no longer admits new requests there after cutover.
    const host=await startHost(plans[e.i],{acceptUntil:slot.endMs-5000});
    hosts.set(e.i,host);
    delete plans[e.i].carrier.secretHex;delete plans[e.i].carrier.epochHex;
    void host.closed.then(()=>{if(!expectedClose.has(e.i)){fault=true;stop();}});
    check(!abort.signal.aborted);
   }else if(e.kind==='select'){
    const host=hosts.get(e.i);
    check(host&&host.authenticatedPeerSeen()===true);
    selected=e.i;
    await onSlot({slot:e.i+1,totalSlots:plans.length,role:host.role,
     authenticatedCellsObserved:true,remoteTransportVerified:false,endsAt:slot.endMs});
   }else if(e.kind==='drain'){selected=null;}
   else{
    check(selected!==e.i);expectedClose.add(e.i);
    const host=hosts.get(e.i);check(host);await host.close();hosts.delete(e.i);finished++;
   }
  }
  return {status:'overlap-schedule-complete',completedSlots:finished,remoteTransportVerified:false};
 }catch(e){
  if(signal?.aborted&&!fault)return {status:'stopped',completedSlots:finished};
  throw e;
 }finally{
  selected=null;stop();signal?.removeEventListener('abort',stop);
  for(const i of hosts.keys())expectedClose.add(i);
  await Promise.allSettled([...hosts.values()].map(h=>h.close()));
  await gateway?.close();
  for(const p of plans){delete p.carrier.secretHex;delete p.carrier.epochHex;}
 }
}
