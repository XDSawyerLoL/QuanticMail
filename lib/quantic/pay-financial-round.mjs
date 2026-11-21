// Fixed-candidate, single-height laboratory composition. No actual PSP or
// money, no migration of single-phase votes, no multi-height consensus.
import {createHash} from 'node:crypto';
import {createCirculationLab} from './pay-circulation-lab.mjs';
import {createPayRoundLab} from './pay-round-lab.mjs';
const check=v=>{if(!v)throw Error('Financial round laboratory refused');};
const sha=b=>createHash('sha256').update(b).digest('hex');
export function openFinancialRound({config,records,proposals,admissionTime}){
 const stable=structuredClone(config),history=structuredClone(records),inputs=structuredClone(proposals);
 const circulation=createCirculationLab(stable),base=circulation.snapshot(history);
 check(Array.isArray(inputs)&&inputs.length>=1&&inputs.length<=16&&Number.isSafeInteger(admissionTime)&&admissionTime>=0);
 const values=new Map();
 for(const proof of inputs){
  const next=circulation.inspectCandidate(history,proof),i=proof.intent;
  check(i.issued<=admissionTime&&admissionTime<i.expires&&next.sequence===base.sequence+1);
  // Include exact authorized intent, hypothetical state and admission epoch.
  // The latter is a lab parameter, not a trusted real-world timestamp.
  const value=sha(Buffer.from(JSON.stringify(['quantic-pay-financial-candidate/v1',base.network,base.root,next.sequence,next.digest,next.root,admissionTime])));
  check(!values.has(value));values.set(value,{proof,next});
 }
 const roundConfig={network:base.network,height:base.sequence+1,previousRoot:base.root,authorities:structuredClone(stable.witnesses),financialCandidates:[...values.keys()].sort()};
 const lab=createPayRoundLab(roundConfig);
 function candidate(value){
  const c=values.get(value);check(c);
  const i=c.proof.intent;
  return Object.freeze({value,payer:i.payer,payee:i.payee,cents:i.cents,currency:'EUR',nonce:i.nonce,previousRoot:base.root,nextRoot:c.next.root,simulationOnly:true});
 }
 function project(certificate){
  const final=lab.finalized(certificate),c=values.get(final.value);check(c);
  const next=circulation.inspectCandidate(history,c.proof);
  check(next.digest===c.next.digest&&next.root===c.next.root);
  return Object.freeze({status:'LAB_ROUND_CERTIFICATE_MATCHED',scope:lab.scope,round:final.round,sequence:next.sequence,previousRoot:base.root,projectedRoot:next.root,balances:next.balances,totalCents:next.totalCents,transaction:candidate(final.value),simulationOnly:true,ledgerCommitted:false,realPaymentAuthorized:false,settlementVerified:false});
 }
 return Object.freeze({scope:lab.scope,roundConfig:()=>structuredClone(roundConfig),candidates:()=>Object.freeze([...values.keys()].map(candidate)),selectView:lab.selectView,project});
}
