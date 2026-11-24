// Trusted-process experimental rotation. No application operation is queued
// or retried here. A new carrier requires a new durable generation.
import {startFencedNegotiatedManagedCarrier} from './native-managed-scattering.mjs';
const check=x=>{if(!x)throw Error('Scattering rotation refused');};
const MAX=4,PERIOD=25*60*1000;
function until(carrier,signal,ms,reason){
 return new Promise(resolve=>{
  let done=false,timer;
  const finish=value=>{if(done)return;done=true;clearTimeout(timer);signal.removeEventListener('abort',abort);resolve(value);};
  const abort=()=>finish('stopped');
  signal.addEventListener('abort',abort,{once:true});
  void carrier.closed.then(()=>finish('carrier-lost'),()=>finish('carrier-lost'));
  timer=setTimeout(()=>finish(reason),ms);
  if(signal.aborted)abort();
 });
}
// Both peers must agree on channel, role, rotation interval and socket/epoch
// provisioning out of band. Relative timers can drift; failed handshake stops.
// Each epoch's private queue/guard directory must be independently provisioned.
export function startScatteringRotation({signer,channel,role,epochs,signal,periodMs=PERIOD,onState=()=>{}},{start=startFencedNegotiatedManagedCarrier,wait=until,now=Date.now}={}){
 check(signer&&typeof signer.authorizeRenewal==='function'&&typeof signer.signHandshake==='function'&&signer.fence&&/^[a-f0-9]{96}$/.test(channel)&&['initiator','responder'].includes(role));
 check(Array.isArray(epochs)&&epochs.length>=1&&epochs.length<=MAX&&Number.isSafeInteger(periodMs)&&periodMs>=1000&&periodMs<=PERIOD&&typeof onState==='function'&&!signal?.aborted);
 const dirs=epochs.flatMap(e=>[e.config?.queueDir,e.config?.stateDir]);
 check(dirs.every(x=>typeof x==='string'&&x.length>0)&&new Set(dirs).size===dirs.length);
 for(const e of epochs)check(e.config?.labOnly===true&&e.config.role===(role==='initiator'?'client':'relay')&&!Object.hasOwn(e.config,'secretHex')&&!Object.hasOwn(e.config,'epochHex'));
 const stop=new AbortController();let current=null;
 const requestStop=()=>{stop.abort();void current?.close();};
 signal?.addEventListener('abort',requestStop,{once:true});
 async function run(){
  try{
   if(stop.signal.aborted)return {status:'stopped'};
   const grant=await signer.authorizeRenewal(channel,role);
   check(Number.isSafeInteger(grant.expires)&&grant.attempts===MAX);
   for(let generation=0;generation<epochs.length;generation++){
    if(stop.signal.aborted)return {status:'stopped'};
    if(grant.expires<=now())return {status:'authorization-expired'};
    onState({status:'negotiating',generation});
    const next=await start({...epochs[generation],local:signer.local,peer:signer.peer,signHandshake:signer.signHandshake,fence:signer.fence,signal:stop.signal});
    current=next;
    if(stop.signal.aborted){await current.close();return {status:'stopped'};}
    check(next.generation===generation&&next.peerReady===true&&typeof next.retire==='function');
    const remaining=grant.expires-now();
    if(remaining<=0)return {status:'authorization-expired'};
    onState({status:'ready',generation,httpPort:next.httpPort});
    const reason=await wait(next,stop.signal,Math.min(remaining,periodMs),remaining<=periodMs?'authorization-expired':'rotate');
    if(reason!=='rotate')return {status:reason};
    // Refuse if the current epoch has an unresolved operation. retire()
    // closes in both cases, and throws if it was not idle. Never replay mail.
    await next.retire();current=null;
   }
   return {status:'authorization-budget-exhausted'};
  }catch{return {status:stop.signal.aborted?'stopped':'failed-no-retry'};}
  finally{
   stop.abort();await current?.close();current=null;
   signal?.removeEventListener('abort',requestStop);
  }
 }
 const closed=run();
 return Object.freeze({closed,close:()=>{requestStop();return closed;}});
}
// Uses a live enrolled Windows controller; no raw private-key inputs.
export function startWindowsScatteringRotation({controller,address,deviceId,...options}){
 check(controller?.lifecycleSignal&&!controller.lifecycleSignal.aborted&&typeof controller.scatteringSigner==='function');
 return startScatteringRotation({...options,signer:controller.scatteringSigner(address,deviceId),signal:options.signal?AbortSignal.any([controller.lifecycleSignal,options.signal]):controller.lifecycleSignal});
}
