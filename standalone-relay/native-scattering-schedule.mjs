// Finite, pre-authorized time-based renewal. Fresh independent secrets per
// slot; no on-demand retries, no reuse, no new cryptographic wire protocol.
// This Linux Alpha schedule is deliberately not an online key agreement.
import {createHash} from 'node:crypto';
import {open,lstat,realpath,constants} from 'node:fs/promises';
import {dirname,resolve,isAbsolute} from 'node:path';
import {performance} from 'node:perf_hooks';
import {setTimeout as sleep} from 'node:timers/promises';
import {loadPrivateCarrierPlan,startPrivateCarrierHost,validatePrivateCarrierPlan} from './native-scattering-host.mjs';
const check=x=>{if(!x)throw Error('Private Scattering renewal refused');};
const hex=/^[a-f0-9]{64}$/;
const exact=(v,ks)=>v&&Object.getPrototypeOf(v)===Object.prototype&&Object.keys(v).length===ks.length&&ks.every(k=>Object.hasOwn(v,k));
const pathOK=p=>typeof p==='string'&&isAbsolute(p)&&resolve(p)===p;
const DRAIN_MS=35000,MIN_SLOT_MS=45000,MAX_SLOT_MS=3600000,GAP_MS=2000,MAX_SLOTS=24;
export const PRIVATE_SCHEDULE_POLICY=Object.freeze({drainMs:DRAIN_MS,minSlotMs:MIN_SLOT_MS,maxSlotMs:MAX_SLOT_MS,gapMs:GAP_MS,maxSlots:MAX_SLOTS});
export function validateCarrierSchedule(spec,plans,{now=Date.now()}={}){
 check(exact(spec,['format','labOnly','slots'])&&spec.format==='quantic-private-scattering-schedule/v1'&&spec.labOnly===true);
 check(Array.isArray(spec.slots)&&spec.slots.length>=2&&spec.slots.length<=MAX_SLOTS&&Array.isArray(plans)&&plans.length===spec.slots.length);
 const used=new Set(),queues=new Set(),files=new Set();
 const first=plans[0];validatePrivateCarrierPlan(first);
 let prev;
 for(let i=0;i<plans.length;i++){
  const s=spec.slots[i],p=plans[i];validatePrivateCarrierPlan(p);
  check(exact(s,['startMs','endMs','file','pin'])&&pathOK(s.file)&&hex.test(s.pin)&&!files.has(s.file));
  files.add(s.file);
  check(Number.isSafeInteger(s.startMs)&&Number.isSafeInteger(s.endMs)&&s.endMs-s.startMs>=MIN_SLOT_MS&&s.endMs-s.startMs<=MAX_SLOT_MS);
  check(s.startMs>=now+500&&s.endMs<=now+24*60*60*1000);
  if(prev)check(s.startMs===prev.endMs+GAP_MS);
  prev=s;
  check(['pacerBinary','pacerSha256','listenIP','listenPort','peerIP','peerPort','periodUs'].every(k=>p[k]===first[k]));
  check(['role','recvPort','httpPort','stateDir'].every(k=>p.carrier[k]===first.carrier[k]));
  check(!queues.has(p.carrier.queueDir)&&p.carrier.queueDir!==first.carrier.stateDir);
  queues.add(p.carrier.queueDir);
  for(const key of [p.carrier.secretHex,p.carrier.epochHex]){check(!used.has(key));used.add(key);}
 }
 return true;
}
export async function loadPrivateCarrierSchedule(file,pin){
 check(process.platform==='linux'&&pathOK(file)&&hex.test(pin)&&await realpath(file)===file);
 const dir=await lstat(dirname(file));
 check(dir.isDirectory()&&dir.uid===process.getuid()&&(dir.mode&0o077)===0);
 const f=await open(file,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
 let spec;
 try{
  const s=await f.stat();check(s.isFile()&&s.uid===process.getuid()&&(s.mode&0o077)===0&&s.nlink===1&&s.size>0&&s.size<=32768);
  const raw=await f.readFile();
  try{check(raw.length===s.size&&createHash('sha256').update(raw).digest('hex')===pin);
   spec=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(raw));}
  finally{raw.fill(0);}
 }finally{await f.close();}
 check(Array.isArray(spec?.slots)&&spec.slots.length>=2&&spec.slots.length<=MAX_SLOTS);
 for(const s of spec.slots)check(exact(s,['startMs','endMs','file','pin'])&&pathOK(s.file)&&dirname(s.file)===dirname(file)&&hex.test(s.pin));
 const plans=[];
 for(const s of spec.slots)plans.push(await loadPrivateCarrierPlan(s.file,s.pin));
 if(spec.format==='quantic-private-scattering-overlap/v1'){
  const {validateOverlapSchedule}=await import('./native-scattering-overlap.mjs');
  validateOverlapSchedule(spec,plans);
 }else validateCarrierSchedule(spec,plans);
 return {spec,plans};
}
export async function runPrivateCarrierSchedule({spec,plans},{
 signal,onSlot=()=>{},startHost=startPrivateCarrierHost,
 now=Date.now,monotonic=()=>performance.now(),
 pause=async(ms,signal)=>sleep(ms,undefined,{signal})
}={}){
 validateCarrierSchedule(spec,plans,{now:now()});
 const baseWall=now(),baseMono=monotonic();
 const verifyClock=()=>{check(Math.abs((now()-baseWall)-(monotonic()-baseMono))<=1000);};
 async function waitUntil(target,activeSignal){
  while(now()<target){
   if(activeSignal?.aborted)throw Error('Schedule cancelled');
   verifyClock();await pause(Math.min(250,target-now()),activeSignal);
  }
  verifyClock();
 }
 let finished=0;
 try{
  for(let i=0;i<plans.length;i++){
   if(signal?.aborted)return {status:'stopped',completedSlots:finished};
   const slot=spec.slots[i],plan=plans[i];
   await waitUntil(slot.startMs,signal);
   // Never catch up or start a partially elapsed schedule after a clock jump.
   check(now()-slot.startMs<=1000&&!signal?.aborted);
   const host=await startHost(plan,{acceptUntil:slot.endMs-DRAIN_MS});
   // Remove the consumed credentials from the in-memory plan. A new slot
   // always uses a new independent pair, never the previous one.
   delete plan.carrier.secretHex;delete plan.carrier.epochHex;
   const slotAbort=new AbortController();
   const abortSlot=()=>slotAbort.abort();
   signal?.addEventListener('abort',abortSlot,{once:true});
   if(signal?.aborted)abortSlot();
   try{
    check(now()<slot.endMs-DRAIN_MS);
    await onSlot({slot:i+1,totalSlots:plans.length,role:host.role,admissionUntil:slot.endMs-DRAIN_MS,
     endsAt:slot.endMs,remoteTransportVerified:false});
    const end=await Promise.race([
     waitUntil(slot.endMs,slotAbort.signal).then(()=>({scheduled:true})),
     host.closed.then(result=>({scheduled:false,result}))
    ]);
    check(end.scheduled);
   }finally{
    slotAbort.abort();signal?.removeEventListener('abort',abortSlot);
    await host.close();
   }
   finished++;
  }
  return {status:'schedule-complete',completedSlots:finished,remoteTransportVerified:false};
 }catch(e){
  if(signal?.aborted)return {status:'stopped',completedSlots:finished};
  throw e;
 }finally{
  for(const p of plans){delete p.carrier.secretHex;delete p.carrier.epochHex;}
 }
}
