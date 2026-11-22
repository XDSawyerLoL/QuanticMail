// Experimental irrevocable cross-shard decision for one reserved transfer.
// One fixed 16-member source committee, 11/16 hybrid votes per phase.
// The same scope covers COMMIT and ABORT; each validator MUST maintain an
// independent durable vote lock. Does not give network liveness or make funds
// real. Expiry alone NEVER authorizes a refund after a COMMIT decision.
// No committee rotation, remote custody, or independently audited checkpoint.
import {createHash} from 'node:crypto';
import {createPayRoundLab} from './pay-round-lab.mjs';
import {openPersistentPayRound} from './pay-round-store.mjs';
const check=v=>{if(!v)throw Error('Cross-shard atomic-decision lab refused');};
const hex=s=>typeof s==='string'&&/^[0-9a-f]{64}$/.test(s);
const shard=s=>typeof s==='string'&&/^demo-[a-z0-9]{1,24}$/.test(s);
const hash=v=>createHash('sha256').update(JSON.stringify(v)).digest('hex');
const exact=(v,keys)=>v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).length===keys.length&&keys.every(k=>Object.hasOwn(v,k));
export function openCrossShardDecisionLab({network,source,destination,transferId,authorities,destinationPreparedRoot=null}){
 check(hex(network)&&hex(transferId)&&shard(source)&&shard(destination)&&source!==destination&&Array.isArray(authorities)&&authorities.length===16&&(destinationPreparedRoot===null||hex(destinationPreparedRoot)));
 const roster=structuredClone(authorities);
 const roundConfig={
  network:hash(['quantic-cross-shard-decision-network/lab/v1',network,source,destination,transferId]),
  height:1,
  previousRoot:hash(['quantic-cross-shard-decision-genesis/lab/v1',network,source,destination,transferId]),
  authorities:roster,admissionRound:true,committeeMode:true
 };
 const round=createPayRoundLab(roundConfig);
 function value(outcome){
  check(outcome==='commit'||outcome==='abort');
  if(outcome==='commit'&&destinationPreparedRoot!==null)return hash(['quantic-cross-shard-prepared-decision/lab/v1',network,source,destination,transferId,'commit',destinationPreparedRoot]);
  return hash(['quantic-cross-shard-decision/lab/v1',network,source,destination,transferId,outcome]);
 }
 function verifyDecision(decision,expectedOutcome=null){
  check(exact(decision,['outcome','certificate'])&&(expectedOutcome===null||decision.outcome===expectedOutcome));
  const resolved=value(decision.outcome),final=round.finalized(decision.certificate);
  check(final.round===0&&final.value===resolved);
  return Object.freeze({outcome:decision.outcome,transferId,network,source,destination,simulationOnly:true,realPaymentAuthorized:false});
 }
 function openAuthority({directory,createNew=false,credentials}){
  const store=openPersistentPayRound({directory,createNew,config:roundConfig,...credentials});
  return Object.freeze({
   status:store.status,
   prepare(outcome){return store.prepare({round:0,value:value(outcome),viewCertificate:null});},
   commit(outcome,prepared){check(prepared?.round===0&&prepared?.value===value(outcome));return store.commit(prepared);},
   close:store.close
  });
 }
 return Object.freeze({scope:round.scope,value,verifyDecision,openAuthority,destinationPreparedRoot,simulationOnly:true});
}
