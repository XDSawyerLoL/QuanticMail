// Pure fail-closed two-stage GUI authorization policy. No network, files or
// implicit retry. The caller must have obtained initial human GUI consent.
export function makeGuiDepositApproval(publishPhase, receiveDecision) {
 if(typeof publishPhase!=='function'||typeof receiveDecision!=='function')throw Error('Missing GUI consent pipe');
 let count=0;
 return async ()=>{
  count++;
  if(count===1)return true; // Initial consent verified by the WinForms caller.
  if(count!==2)return false; // Never auto-authorize a second attempt.
  publishPhase({phase:'sealed-awaiting-deposit-approval'});
  return (await receiveDecision())==='SEND'; // Exact, case-sensitive one-shot permission.
 };
}
