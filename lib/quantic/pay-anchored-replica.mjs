// Standard fail-closed external checkpoint compare-and-swap guard.
// Trusted synchronous anchor MUST be independently durable, non-rollbackable
// and authenticated; exclusive replica ownership is required. No real funds.
import {assertExternalPayCheckpoint} from './pay-external-checkpoint.mjs';
import {openPayRoundReplica} from './pay-round-replica.mjs';
const check=v=>{if(!v)throw Error('Anchored Pay replica refused');};
export function openAnchoredPayReplica({anchor,...options}){
 check(options.config?.admissionPolicy==='round-v3'&&options.createNew!==true&&options.expectedCheckpoint===undefined);
 check(typeof anchor?.read==='function'&&typeof anchor?.compareAndSwap==='function');
 const expected=structuredClone(anchor.read());
 check(expected!==null&&expected!==undefined);
 const node=openPayRoundReplica({...options,expectedCheckpoint:expected});
 let halted=false,closed=false,busy=false;
 const reads=['status','record','checkpoint'];
 const writes=['admissionPrepare','admissionChange','admissionCommit','admit','prepare','changeView','commitVote','learn'];
 function perform(op,args,mutating){
  check(!closed&&!halted&&!busy);busy=true;
  try{
   const before=node.checkpoint();
   assertExternalPayCheckpoint(before,anchor.read());
   const result=node[op](...args);
   const after=node.checkpoint();
   if(mutating){
    // The vote or receipt must not leave this API until external storage
    // acknowledges its durable checkpoint. Ambiguous outcome stops the node.
    check(anchor.compareAndSwap(structuredClone(before),structuredClone(after))===true);
   }else assertExternalPayCheckpoint(after,before);
   assertExternalPayCheckpoint(after,anchor.read());
   return result;
  }catch(e){halted=true;throw Error('Anchored Pay replica halted; independent reconciliation required',{cause:e});}
  finally{busy=false;}
 }
 const api={};
 for(const op of reads)api[op]=(...args)=>perform(op,args,false);
 for(const op of writes)api[op]=(...args)=>perform(op,args,true);
 return Object.freeze({...api,anchorStatus:()=>({halted,closed,simulationOnly:true}),close(){check(!busy);if(!closed){closed=true;node.close();}}});
}
