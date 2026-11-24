// Mandatory before/after quorum for a fictional payment session.
// External callbacks must be independently configured and authenticated.
// This is not a distributed commit protocol or a real payment authorization.
import {randomBytes} from 'node:crypto';
import {newPayCheckpointRequest,reconcilePayCheckpoint,verifyHistoricalPayProof,summarizePayProofs} from './pay-lab-checkpoint.mjs';
import {PAYEES,parseDemoAmount,START_CENTS} from './pay-sandbox.mjs';
const check=v=>{if(!v)throw Error('Pay quorum simulation refused');};
export function createPayQuorumFlow({scope,trustedAuthorities,readVotes,signProof,submitProof,initialProofs=[],clock=Date.now}){
 check([readVotes,signProof,submitProof,clock].every(f=>typeof f==='function'));
 const pins=Object.freeze({...scope}),trusted=structuredClone(trustedAuthorities);
 let history=structuredClone(initialProofs),busy=false,halted=false;
 summarizePayProofs(history,pins);
 const total=()=>history.reduce((n,p)=>n+verifyHistoricalPayProof(p,pins).cents,0);
 check(total()<=START_CENTS);
 const snapshot=()=>Object.freeze({simulationOnly:true,realPaymentAuthorized:false,halted,pending:busy,balanceCents:START_CENTS-total(),proofCount:history.length});
 const reconcile=async proofs=>{
  const request=newPayCheckpointRequest(pins,clock());
  const attestations=await readVotes(request);
  return reconcilePayCheckpoint({localProofs:proofs,request,trustedAuthorities:trusted,attestations,now:clock()});
 };
 return Object.freeze({snapshot,async confirm({payeeId,amount,explicitConsent}){
  check(!busy&&!halted&&explicitConsent===true&&PAYEES.some(p=>p.id===payeeId));
  const cents=parseDemoAmount(amount);check(cents<=snapshot().balanceCents&&history.length<100);
  busy=true;
  try{
   const pre=await reconcile(history);
   const issued=clock();check(Number.isSafeInteger(issued)&&issued>=0&&issued<=Number.MAX_SAFE_INTEGER-120000);
   const intent=Object.freeze({Payee:payeeId,Cents:cents,Nonce:randomBytes(32).toString('hex'),Issued:issued,Expires:issued+120000});
   const proof=structuredClone(await signProof(intent));
   const verified=verifyHistoricalPayProof(proof,pins);
   check(verified.nonce===intent.Nonce&&proof.intent.Payee===intent.Payee&&proof.intent.Cents===intent.Cents&&proof.intent.Issued===intent.Issued&&proof.intent.Expires===intent.Expires);
   check(clock()>=issued&&clock()<intent.Expires);
   const next=[...history,proof];summarizePayProofs(next,pins);
   // Any uncertain result from this point requires operator reconciliation.
   // Never automatically retry, mint a fresh nonce or report a settled debit.
   await submitProof(structuredClone(proof),Object.freeze({count:pre.proofCount,root:pre.root}));
   const post=await reconcile(next);
   check(post.proofCount===pre.proofCount+1&&clock()>=issued&&clock()<intent.Expires);
   history=next;
   return Object.freeze({status:'simulated-quorum-confirmed',simulationOnly:true,realPaymentAuthorized:false,settlementVerified:false,nonce:verified.nonce,proofCount:post.proofCount,witnessCount:post.witnessCount,balanceCents:START_CENTS-total()});
  }catch(e){halted=true;throw e;}finally{busy=false;}
 }});
}
