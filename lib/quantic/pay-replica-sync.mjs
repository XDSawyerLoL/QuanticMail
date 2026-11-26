// Explicit bounded synchronization of provisioned peers, no coordinator ledger.
// Remote status is a hint, never authority to alter financial state.
// A receiving replica independently verifies and persists each certificate.
const check=v=>{if(!v)throw Error('Replica synchronization refused');};
const hex=/^[a-f0-9]{64}$/;
export async function synchronizePayReplica({network,targetPin,target,peers,maxSteps=4}){
 check(hex.test(network)&&hex.test(targetPin)&&Array.isArray(peers)&&peers.length>=1&&peers.length<=3&&Number.isInteger(maxSteps)&&maxSteps>=1&&maxSteps<=4);
 const pins=new Set([targetPin]);
 for(const p of peers){check(hex.test(p.authorityPin)&&!pins.has(p.authorityPin));pins.add(p.authorityPin);}
 function validate(s,pin){
  check(s?.simulationOnly===true&&s.network===network&&s.authorityPin===pin&&Number.isInteger(s.sequence)&&s.sequence>=0&&s.sequence<=32&&typeof s.root==='string'&&hex.test(s.root));return s;
 }
 let local=validate(await target.status(),targetPin),applied=0;
 const sources=[];
 for(const p of peers){
  try{const state=validate(await p.client.status(),p.authorityPin);sources.push({...p,state});}catch{/* Unavailable or mismatched peers cannot supply status hints. */}
 }
 if(!sources.length)return Object.freeze({state:'no-verified-peer-status',sequence:local.sequence,applied,simulationOnly:true});
 const max=Math.max(local.sequence,...sources.map(p=>p.state.sequence));
 while(local.sequence<max&&applied<maxSteps){
  const height=local.sequence+1;let fetched=false;
  for(const p of sources.filter(p=>p.state.sequence>=height)){
   let record;
   try{record=await p.client.record(height);}catch{continue;}
   // A failed learn might have committed before a response was lost. Never
   // blindly retry or use another peer after an ambiguous mutation.
   try{
    const receipt=await target.learn(record);
    check(receipt?.simulationOnly===true&&receipt.sequence===height&&receipt.realPaymentAuthorized===false);
    const next=validate(await target.status(),targetPin);
    check(next.sequence===height&&next.root===receipt.root);
    local=next;applied++;fetched=true;break;
   }catch{return Object.freeze({state:'reconcile-required',sequence:local.sequence,applied,simulationOnly:true});}
  }
  if(!fetched)return Object.freeze({state:'missing-certified-record',sequence:local.sequence,applied,simulationOnly:true});
 }
 const divergent=sources.some(p=>p.state.sequence===local.sequence&&p.state.root!==local.root);
 return Object.freeze({state:divergent?'peer-root-mismatch':local.sequence<max?'batch-limit':'caught-up-to-observed-peers',sequence:local.sequence,root:local.root,applied,simulationOnly:true});
}
