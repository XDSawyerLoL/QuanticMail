// Fixed-height synthetic batch experiment, deliberately separate from the live chain.
// No persistence, cross-shard finality, live identity or actual money.
import {createHash} from 'node:crypto';
import {createRoundCirculationLab} from './pay-circulation-lab.mjs';
import {createPayRoundLab} from './pay-round-lab.mjs';
const check=v=>{if(!v)throw Error('Pay batch laboratory refused');};
const hash=v=>createHash('sha256').update(JSON.stringify(v)).digest('hex');
const hex=v=>typeof v==='string'&&/^[a-f0-9]{64}$/.test(v);
const exact=(o,k)=>o&&typeof o==='object'&&!Array.isArray(o)&&Object.keys(o).length===k.length&&k.every(x=>Object.hasOwn(o,x));
const leaf=p=>hash(['quantic-pay-batch-leaf/v1',p.intent.network,p.intent.sequence,p.intent.previousRoot,p.intent.payer,p.intent.payee,p.intent.payerPin,p.intent.payerPQPin,p.intent.payeePin,p.intent.payeePQPin,p.intent.cents,p.intent.currency,p.intent.nonce,p.intent.issued,p.intent.expires,p.intent.simulationOnly,p.signature,p.pqSignature]);
const parent=(a,b)=>hash(['quantic-pay-batch-node/v1',a,b]);
const MAX=1024;
function tree(leaves){
 const levels=[leaves];while(levels.at(-1).length>1){const a=levels.at(-1),b=[];for(let i=0;i<a.length;i+=2)b.push(parent(a[i],a[i+1]??a[i]));levels.push(b);}return levels;
}
export function openPayBatchLab({config,records=[]}){
 const cfg=structuredClone(config),history=structuredClone(records);
 check(cfg.admissionPolicy==='round-v3'&&cfg.witnesses.length===16);
 const chain=createRoundCirculationLab(cfg),base=chain.snapshot(history);
 check(base.sequence<32);
 const roundConfig={network:hash(['quantic-pay-batch-network/v1',base.network]),height:base.sequence+1,previousRoot:base.root,authorities:cfg.witnesses,admissionRound:true,committeeMode:true};
 const round=createPayRoundLab(roundConfig);
 function inspect(p,time){
  const v=chain.inspectCandidate(history,p);
  check(p.intent.issued<=time&&time<p.intent.expires);
  return v;
 }
 function validateHeader(h){
  check(exact(h,['network','height','previousRoot','count','merkleRoot','stateRoot','admissionTime'])&&h.network===base.network&&h.height===base.sequence+1&&h.previousRoot===base.root&&Number.isInteger(h.count)&&h.count>=1&&h.count<=MAX&&hex(h.merkleRoot)&&hex(h.stateRoot)&&Number.isSafeInteger(h.admissionTime)&&h.admissionTime>=0);
  return hash(['quantic-pay-batch-decision/v1',h.network,h.height,h.previousRoot,h.count,h.merkleRoot,h.stateRoot,h.admissionTime]);
 }
 function propose(proofs,time){
  check(Array.isArray(proofs)&&proofs.length>=1&&proofs.length<=MAX&&Number.isSafeInteger(time)&&time>=0);
  const inputs=structuredClone(proofs),seen=new Set(),spent=new Map(),balances={...base.balances};
  const rows=inputs.map(p=>{
   inspect(p,time);const i=p.intent;check(!seen.has(i.nonce));seen.add(i.nonce);
   const n=(spent.get(i.payer)??0)+i.cents;check(Number.isSafeInteger(n)&&n<=base.balances[i.payer]);spent.set(i.payer,n);
   balances[i.payer]-=i.cents;balances[i.payee]+=i.cents;
   return {proof:p,leaf:leaf(p)};
  }).sort((a,b)=>a.leaf<b.leaf?-1:a.leaf>b.leaf?1:0);
  check(Object.values(balances).every(n=>Number.isSafeInteger(n)&&n>=0)&&Object.values(balances).reduce((a,b)=>a+b,0)===base.totalCents);
  const levels=tree(rows.map(r=>r.leaf)),header={network:base.network,height:base.sequence+1,previousRoot:base.root,count:rows.length,merkleRoot:levels.at(-1)[0],stateRoot:hash(['quantic-pay-batch-state/v1',base.root,levels.at(-1)[0],Object.entries(balances).sort()]),admissionTime:time};
  const value=validateHeader(header);
  function receipt(index,certificate){
   check(Number.isInteger(index)&&index>=0&&index<rows.length);
   check(round.finalized(certificate).value===value);
   const siblings=[];let j=index;
   for(const l of levels.slice(0,-1)){siblings.push(l[j^1]??l[j]);j=Math.floor(j/2);}
   return {header:structuredClone(header),proof:structuredClone(rows[index].proof),index,siblings,certificate:structuredClone(certificate),simulationOnly:true,realPaymentAuthorized:false};
  }
  return Object.freeze({header:Object.freeze(header),value,balances:Object.freeze(balances),receipt});
 }
 function verifyReceipt(r){
  check(exact(r,['header','proof','index','siblings','certificate','simulationOnly','realPaymentAuthorized'])&&r.simulationOnly===true&&r.realPaymentAuthorized===false);
  const h=r.header,value=validateHeader(h);check(round.finalized(r.certificate).value===value);
  inspect(r.proof,h.admissionTime);
  check(Number.isInteger(r.index)&&r.index>=0&&r.index<h.count&&Array.isArray(r.siblings)&&r.siblings.length===Math.ceil(Math.log2(h.count)));
  let j=r.index,n=h.count,x=leaf(r.proof);
  for(const s of r.siblings){check(hex(s));if((j^1)>=n)check(s===x);x=j%2?parent(s,x):parent(x,s);j=Math.floor(j/2);n=Math.ceil(n/2);}
  check(x===h.merkleRoot&&n===1);
  return Object.freeze({included:true,simulationOnly:true,realPaymentAuthorized:false,nonce:r.proof.intent.nonce,root:h.stateRoot});
 }
 // These in-memory authorities must independently verify the full proposed batch.
 // One instance per trusted authority/height. This wrapper supplies no durable anti-rollback.
 function openAuthority(credentials){
  const a=round.openAuthority(credentials);
  return Object.freeze({prepare({proofs,time,round:r=0,viewCertificate=null,value}){check(propose(proofs,time).value===value);return a.prepare({round:r,value,viewCertificate});},commit:a.commit,learn:a.learn,changeView:a.changeView});
 }
 return Object.freeze({scope:round.scope,committee:round.committee,propose,openAuthority,verifyReceipt});
}
