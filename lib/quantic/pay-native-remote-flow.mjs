// Compose the native receipt inventory and dedicated witness carrier client.
// A read-only startup reconciliation is mandatory; no witness initialization
// from local history, no automatic retry, no real payment.
import {createPayQuorumFlow} from './pay-quorum-flow.mjs';
import {newPayCheckpointRequest,reconcilePayCheckpoint,summarizePayProofs} from './pay-lab-checkpoint.mjs';
import {createPayWitnessQuorumClient} from './pay-witness-quorum-client.mjs';
const check=v=>{if(!v)throw Error('Pay remote laboratory refused');};
export async function openNativePayRemoteFlow({scope,trustedAuthorities,links,readHistory,signNative,clock=Date.now}){
 check(typeof readHistory==='function'&&typeof signNative==='function');
 const stableScope=Object.freeze({...scope}),trusted=structuredClone(trustedAuthorities);
 const carrier=createPayWitnessQuorumClient(links);
 const local=structuredClone(await readHistory());
 const expected=summarizePayProofs(local,stableScope);
 const request=newPayCheckpointRequest(stableScope,clock());
 const attestations=await carrier.readVotes(request);
 reconcilePayCheckpoint({localProofs:local,request,trustedAuthorities:trusted,attestations,now:clock()});
 let current=expected;
 return createPayQuorumFlow({scope:stableScope,trustedAuthorities:trusted,...carrier,initialProofs:local,clock,
  signProof:async intent=>{
   const before=structuredClone(await readHistory()),previous=summarizePayProofs(before,stableScope);
   check(previous.count===current.count&&previous.root===current.root);
   const proof=structuredClone(await signNative(intent));
   const actual=summarizePayProofs(await readHistory(),stableScope);
   const next=summarizePayProofs([...before,proof],stableScope);
   check(actual.count===next.count&&actual.root===next.root);
   current=next;return proof;
  }
 });
}
