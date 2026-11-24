// One freshly provisioned carrier epoch per logical committee operation.
// The trusted provisioning callback must reserve matching native endpoints,
// authenticate the peer independently, and retain epoch consumption markers.
// The manager cannot establish those guarantees merely from an epoch ID.
import {createPayReplicaCarrier} from './pay-replica-carrier.mjs';
const check=v=>{if(!v)throw Error('Committee session refused');};
const hex=v=>typeof v==='string'&&/^[a-f0-9]{64}$/.test(v)&&!/^0+$/.test(v);
const voteOps=['admissionPrepare','admissionChange','admissionCommit','admit','prepare','changeView','commitVote'];
const recoveryOps=['record','learn'];
export function createCommitteeSession({network,authorityPin,provision,maxEpochs=64}){
 check(hex(network)&&hex(authorityPin)&&typeof provision==='function'&&Number.isInteger(maxEpochs)&&maxEpochs>=1&&maxEpochs<=256);
 const consumed=new Set();
 let busy=false,halted=false,closed=false,started=0;
 async function run(op,input,profile){
  check(!closed&&!halted&&!busy&&started<maxEpochs);
  const voting=profile==='vote',snapshot=structuredClone(input);
  check(voting?voteOps.includes(op)||op==='status':recoveryOps.includes(op)||op==='status');
  busy=true;started++;
  let lease,result,failure;
  try{
   lease=await provision(Object.freeze({network,authorityPin,profile,operation:op}));
   check(lease&&lease.network===network&&lease.authorityPin===authorityPin&&lease.profile===profile&&hex(lease.epochId)&&typeof lease.close==='function'&&!consumed.has(lease.epochId));
   consumed.add(lease.epochId);
   const c=createPayReplicaCarrier({loopbackPort:lease.loopbackPort,token:lease.token,network,committeeMode:true,voting});
   result=await c[op](snapshot);
  }catch(e){failure=e;halted=true;}
  finally{
   if(typeof lease?.close==='function')try{await lease.close();}catch(e){halted=true;failure??=e;}
   busy=false;
  }
  if(failure)throw Error('Committee session stopped; explicit reconciliation required: '+failure.message,{cause:failure});
  return result;
 }
 const client={status:()=>run('status',null,'recovery'),record:h=>run('record',h,'recovery'),learn:r=>run('learn',r,'recovery')};
 for(const op of voteOps)client[op]=input=>run(op,input,'vote');
 return Object.freeze({...client,sessionStatus:()=>Object.freeze({epochsStarted:started,epochsConsumed:consumed.size,halted,closed,busy,simulationOnly:true}),close(){check(!busy);closed=true;}});
}
