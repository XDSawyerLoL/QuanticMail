// Read-only recovery classification. No new signature, retry, deletion,
// refund, real payment or inferred final settlement.
import {reconcilePayCheckpoint,verifyHistoricalPayProof,summarizePayProofs} from './pay-lab-checkpoint.mjs';
export function inspectInterruptedPay({localProofs,nonce,request,trustedAuthorities,attestations,now=Date.now()}){
 const full=summarizePayProofs(localProofs,request);
 if(typeof nonce!=='string'||!/^[a-f0-9]{64}$/.test(nonce))throw Error('Explicit pending nonce required');
 const matches=localProofs.filter(p=>p.intent.Nonce===nonce);
 if(matches.length!==1)throw Error('Pending proof absent or ambiguous');
 const candidate=verifyHistoricalPayProof(matches[0],request);
 const prior=localProofs.filter(p=>p.intent.Nonce!==nonce);
 function reconcile(proofs){
  try{return reconcilePayCheckpoint({localProofs:proofs,request,trustedAuthorities,attestations,now});}catch{return null;}
 }
 const after=reconcile(localProofs),before=after?null:reconcile(prior);
 return Object.freeze({simulationOnly:true,nonce,candidateDigest:candidate.digest,localRoot:full.root,
  state:after?'quorum-matches-complete-history':before?'quorum-matches-history-without-candidate':'unresolved',
  witnessCount:after?.witnessCount??before?.witnessCount??0,
  resumeRequiresNewStartupQuorum:true,automaticRetryAuthorized:false,deleteAuthorized:false,realPaymentAuthorized:false,settlementVerified:false});
}
