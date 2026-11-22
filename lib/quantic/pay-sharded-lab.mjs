// Synthetic fixed-membership sharded ledger. In-memory, one state machine per
// shard, no real funds. Debit then certified claim, no unilateral refund.
// Pending credits may remain locked indefinitely. No atomic availability claim.
// Honest validators must maintain non-rollback state, one vote per height.
import {createHash,createPublicKey,verify} from 'node:crypto';
import {createPayRoundLab} from './pay-round-lab.mjs';
import {openCommitteeHandoffLab} from './pay-committee-handoff-lab.mjs';
import {verifyHistoricalPayProof} from './pay-lab-checkpoint.mjs';
const check=v=>{if(!v)throw Error('Sharded Pay laboratory refused');};
const hash=v=>createHash('sha256').update(JSON.stringify(v)).digest('hex');
const hex=s=>typeof s==='string'&&/^[a-f0-9]{64}$/.test(s);
const id=s=>typeof s==='string'&&/^demo-[a-z0-9]{1,24}$/.test(s);
const integer=(n,max=Number.MAX_SAFE_INTEGER)=>Number.isSafeInteger(n)&&n>=0&&n<=max;
const exact=(o,ks)=>o&&typeof o==='object'&&!Array.isArray(o)&&Object.keys(o).length===ks.length&&ks.every(k=>Object.hasOwn(o,k));
const sig=(s,n)=>{check(typeof s==='string'&&s.length===Math.ceil(n*8/6)&&/^[A-Za-z0-9_-]+$/.test(s));const b=Buffer.from(s,'base64url');check(b.length===n&&b.toString('base64url')===s);return b;};
const key=(s,n,type)=>{const b=sig(s,n),k=createPublicKey({key:b,format:'der',type:'spki'});check(k.asymmetricKeyType===type&&k.export({format:'der',type:'spki'}).equals(b));if(type==='ec')check(k.asymmetricKeyDetails.namedCurve==='prime256v1');return k;};
const MAX=256, LIMIT=64;
export function openShardedPayLab(config,{rotationEnabled=false,reservationsEnabled=false}={}){
 check(typeof rotationEnabled==='boolean'&&typeof reservationsEnabled==='boolean');
 check(exact(config,['shards','wallets'])&&Array.isArray(config.shards)&&config.shards.length>=2&&config.shards.length<=16&&Array.isArray(config.wallets)&&config.wallets.length>=2&&config.wallets.length<=256);
 const shards=new Map(),wallets=new Map(),pins=new Set();
 for(const s of structuredClone(config.shards)){
  check(exact(s,['id','authorities'])&&id(s.id)&&!shards.has(s.id)&&Array.isArray(s.authorities)&&s.authorities.length===16);
  for(const a of s.authorities){check(hex(a.pin)&&hex(a.pqPin)&&!pins.has(a.pin)&&!pins.has(a.pqPin)&&a.pin!==a.pqPin);pins.add(a.pin);pins.add(a.pqPin);}
  shards.set(s.id,s);
 }
 for(const w of structuredClone(config.wallets)){
  check(exact(w,['id','shard','initial','publicKey','pqPublicKey'])&&id(w.id)&&!wallets.has(w.id)&&shards.has(w.shard)&&integer(w.initial,1000000000));
  wallets.set(w.id,{...w,cl:key(w.publicKey,91,'ec'),pq:key(w.pqPublicKey,1974,'ml-dsa-65')});
 }
 const network=hash([reservationsEnabled?'quantic-shards-reservations/lab/v1':'quantic-shards/lab/v1',[...shards.values()].sort((a,b)=>a.id.localeCompare(b.id)).map(s=>[s.id,s.authorities.map(a=>[a.pin,a.pqPin]).sort()]),[...wallets.values()].sort((a,b)=>a.id.localeCompare(b.id)).map(w=>[w.id,w.shard,w.initial,w.publicKey,w.pqPublicKey])]);
 const genesis=s=>hash(['quantic-shard-genesis/v1',network,s]);
 // Opt-in in-memory rotation laboratory. The durable fixed-roster engine
 // remains unchanged; no crash-safe handoff or external freshness service.
 const histories=new Map(),handoffs=new Map(),owners=new Map();
 if(rotationEnabled)for(const [s,cfg] of shards){
  histories.set(s,[{start:1,epoch:0,tip:null,members:cfg.authorities}]);
  handoffs.set(s,openCommitteeHandoffLab({network,shard:s,initialMembers:cfg.authorities}));
  for(const a of cfg.authorities){owners.set(a.pin,s);owners.set(a.pqPin,s);}
 }
 function round(s,height,previous){
  check(shards.has(s)&&integer(height,MAX)&&height>=1&&hex(previous));
  const e=rotationEnabled?histories.get(s).findLast(e=>e.start<=height):null;
  const domain=e&&e.epoch>0?['quantic-shard-epoch-round/lab/v1',network,s,e.epoch,e.tip]:['quantic-shard-round/v1',network,s];
  return createPayRoundLab({network:hash(domain),height,previousRoot:previous,authorities:e?.members??shards.get(s).authorities,admissionRound:true,committeeMode:true});
 }
 function installHandoff(s,record,checkpoint,anchor){
  check(rotationEnabled&&anchor?.shard===s&&anchor.height<MAX);
  verifyCheckpoint(checkpoint,anchor);
  const handoff=handoffs.get(s),prior=handoff.current(),retained=new Set(prior.members.flatMap(m=>[m.pin,m.pqPin]));
  check(Array.isArray(record?.proposal?.nextMembers)&&record.proposal.nextMembers.length===16);
  // No simultaneous cross-shard membership or reuse of a retired key.
  for(const m of record.proposal.nextMembers)for(const k of [m.pin,m.pqPin])check(!owners.has(k)||(owners.get(k)===s&&retained.has(k)));
  const result=handoff.apply(record,anchor),members=handoff.current().members;
  for(const m of members){owners.set(m.pin,s);owners.set(m.pqPin,s);}
  histories.get(s).push({start:result.activationHeight,epoch:result.epoch,tip:result.tip,members});
  return result;
 }
 function intentBytes(i){
  check(exact(i,['network','payer','payee','amount','nonce'])&&i.network===network&&wallets.has(i.payer)&&wallets.has(i.payee)&&i.payer!==i.payee&&integer(i.amount,1000000000)&&i.amount>0&&hex(i.nonce));
  return Buffer.from(JSON.stringify(['quantic-shard-transfer/v1',i.network,i.payer,i.payee,i.amount,i.nonce]));
 }
 function inspect(p){
  check(exact(p,['intent','signature','pqSignature']));const b=intentBytes(p.intent),w=wallets.get(p.intent.payer);
  check(verify('sha256',b,{key:w.cl,dsaEncoding:'ieee-p1363'},sig(p.signature,64))&&verify(null,b,w.pq,sig(p.pqSignature,3309)));
  const i=p.intent;return {proof:{intent:{network:i.network,payer:i.payer,payee:i.payee,amount:i.amount,nonce:i.nonce},signature:p.signature,pqSignature:p.pqSignature},id:hash(['quantic-shard-id/v1',b.toString('hex')]),nonce:hash(['quantic-shard-nonce/v1',network,i.payer,i.nonce]),source:w.shard,destination:wallets.get(i.payee).shard};
 }
 function value(h){check(exact(h,['network','shard','height','previous','operationsRoot','stateRoot'])&&h.network===network&&shards.has(h.shard)&&integer(h.height,MAX)&&h.height>=1&&hex(h.previous)&&hex(h.operationsRoot)&&hex(h.stateRoot));return hash(['quantic-shard-block/v1',h.network,h.shard,h.height,h.previous,h.operationsRoot,h.stateRoot]);}
 // All reservation operations commit their complete authentication evidence
 // to the quorum-certified Merkle root, not merely their effects on balances.
 function opHash(op){
  if(op.kind==='debit')return hash(['quantic-shard-op/v1','debit',inspect(op.proof).proof]);
  if(op.kind==='reserve')return hash(['quantic-shard-op/v1','reserve',inspect(op.proof).proof]);
  if(op.kind==='capture')return hash(['quantic-shard-op/v1','capture',inspect(op.proof).proof,op.approval]);
  if(op.kind==='cancel')return hash(['quantic-shard-op/v1','cancel',inspect(op.proof).proof,op.signature,op.pqSignature]);
  check(op.kind==='claim');return hash(['quantic-shard-op/v1','claim',op.receipt]);
 }
 function checkApproval(d,approval){
  check(reservationsEnabled&&exact(approval,['intent','signingPin','pqPin','classicalSignature','pqSignature','classicalPublic','pqPublic','realPaymentAuthorized']));
  const w=wallets.get(d.proof.intent.payer),i=d.proof.intent;
  check(i.payee==='demo-shop'||i.payee==='demo-person');
  check(approval.intent?.Payee===i.payee&&approval.intent.Cents===i.amount&&approval.intent.Nonce===i.nonce);
  const signingPin=createHash('sha256').update(Buffer.from(w.publicKey,'base64url')).digest('hex');
  const pqPin=createHash('sha256').update(Buffer.from(w.pqPublicKey,'base64url')).digest('hex');
  verifyHistoricalPayProof(approval,{signingPin,pqPin});
 }
 function cancelBytes(d){return Buffer.from(JSON.stringify(['quantic-shard-cancel-reservation/v1',network,d.id,d.proof.intent.payer,d.proof.intent.nonce]));}
 function heldEntries(m){return [...m.entries()].sort((a,b)=>a[0].localeCompare(b[0]));}
 function stateRoot(b,s,c,h){
  return reservationsEnabled?hash(['quantic-shard-state-reserved/v1',Object.entries(b).sort(),[...s].sort(),[...c].sort(),heldEntries(h)])
    :hash(['quantic-shard-state/v1',Object.entries(b).sort(),[...s].sort(),[...c].sort()]);
 }
 const merkle=leaves=>{let a=leaves;while(a.length>1){const b=[];for(let i=0;i<a.length;i+=2)b.push(hash(['quantic-shard-node/v1',a[i],a[i+1]??a[i]]));a=b;}return a[0];};
 function verifyDebitInternal(receipt,verified=null){
  const capture=reservationsEnabled&&receipt?.kind==='capture';
  check((capture?exact(receipt,['kind','header','certificate','proof','approval','index','count','siblings']):exact(receipt,['header','certificate','proof','index','count','siblings']))&&integer(receipt.count,LIMIT)&&receipt.count>=1&&integer(receipt.index,receipt.count-1)&&Array.isArray(receipt.siblings)&&receipt.siblings.length===Math.ceil(Math.log2(receipt.count)));
  const d=inspect(receipt.proof),h=receipt.header;check(d.source!==d.destination&&h.shard===d.source);
  if(capture)checkApproval(d,receipt.approval);
  const v=value(h);
  // Scoped only to this proposal. Equal exact certificate bytes and header
  // commitment, not merely an equal claimed root. Every wallet signature
  // and Merkle inclusion proof is still independently verified.
  const certBytes=JSON.stringify(receipt.certificate);
  check(typeof certBytes==='string'&&Buffer.byteLength(certBytes)<=200000);
  const cacheKey=hash(['quantic-shard-verified-cert/v1',v,certBytes]);
  if(!verified?.has(cacheKey)){
   check(round(h.shard,h.height,h.previous).finalized(receipt.certificate).value===v);
   verified?.add(cacheKey);
  }
  let x=opHash(capture?{kind:'capture',proof:d.proof,approval:receipt.approval}:{kind:'debit',proof:d.proof}),j=receipt.index,n=receipt.count;
  for(const sib of receipt.siblings){check(hex(sib));if((j^1)>=n)check(sib===x);x=j%2?hash(['quantic-shard-node/v1',sib,x]):hash(['quantic-shard-node/v1',x,sib]);j=Math.floor(j/2);n=Math.ceil(n/2);}
  check(hash(['quantic-shard-operations/v1',receipt.count,x])===h.operationsRoot);return d;
 }
 function verifyDebit(receipt){return verifyDebitInternal(receipt);}
 // A checkpoint is an independently verifiable certified snapshot, not
 // permission to restart a validator. The expected anchor MUST be obtained
 // independently of the snapshot, with a non-rollback source of freshness.
 function verifyCheckpoint(input,expected){
  check(exact(expected,['network','shard','height','root'])&&expected.network===network&&shards.has(expected.shard)&&integer(expected.height,MAX)&&expected.height>=1&&hex(expected.root));
  check(exact(input,reservationsEnabled?['header','certificate','balances','spent','claimed','holds','simulationOnly','realPaymentAuthorized']:['header','certificate','balances','spent','claimed','simulationOnly','realPaymentAuthorized'])&&input.simulationOnly===true&&input.realPaymentAuthorized===false);
  const h=input.header,v=value(h);check(h.shard===expected.shard&&h.height===expected.height&&v===expected.root);
  const final=round(h.shard,h.height,h.previous).finalized(input.certificate);
  check(final.value===v);
  const ids=[...wallets.values()].filter(w=>w.shard===h.shard).map(w=>w.id).sort();
  check(exact(input.balances,ids));
  const supply=[...wallets.values()].reduce((n,w)=>n+w.initial,0);
  check(Object.values(input.balances).every(n=>integer(n,supply))&&Object.values(input.balances).reduce((a,b)=>a+b,0)<=supply);
  for(const list of [input.spent,input.claimed])check(Array.isArray(list)&&list.length<=h.height*LIMIT&&list.every((r,i)=>hex(r)&&(i===0||list[i-1]<r)));
  const restoredHolds=new Map();
  if(reservationsEnabled){
   check(Array.isArray(input.holds)&&input.holds.length<=MAX);
   let prior='';
   for(const pair of input.holds){
    check(Array.isArray(pair)&&pair.length===2&&hex(pair[0])&&pair[0]>prior);prior=pair[0];
    const d=inspect(pair[1]);check(d.id===pair[0]&&d.source===h.shard&&input.spent.includes(d.nonce));
    restoredHolds.set(d.id,d.proof);
   }
  }
  check(stateRoot(input.balances,new Set(input.spent),new Set(input.claimed),restoredHolds)===h.stateRoot);
  return Object.freeze({network,shard:h.shard,height:h.height,root:v,balances:Object.freeze({...input.balances}),spent:input.spent.length,claimed:input.claimed.length,simulationOnly:true,realPaymentAuthorized:false});
 }
 const opened=new Set();
 function openShard(shard,restore=null){
  check(shards.has(shard)&&!opened.has(shard));let height=0,root=genesis(shard),balance=Object.fromEntries([...wallets.values()].filter(w=>w.shard===shard).map(w=>[w.id,w.initial])),spent=new Set(),claimed=new Set(),holds=new Map();
  let active=null,lastHeader=null,lastCertificate=null,frozen=false;
  // Restore ONLY an observer: the checkpoint certifies committed state, not
  // uncommitted vote locks at the next height. Never enable voting from it.
  const observerOnly=restore!==null;
  if(observerOnly){
   check(exact(restore,['checkpoint','anchor']));
   const input=structuredClone(restore.checkpoint),v=verifyCheckpoint(input,restore.anchor);
   check(v.shard===shard);height=v.height;root=v.root;balance={...input.balances};
   spent=new Set(input.spent);claimed=new Set(input.claimed);holds=reservationsEnabled?new Map(input.holds):new Map();
   lastHeader=structuredClone(input.header);lastCertificate=structuredClone(input.certificate);
  }
  opened.add(shard);
  function propose(operations){
   check(!frozen&&Array.isArray(operations)&&operations.length>=1&&operations.length<=LIMIT&&height<MAX);
   const ops=structuredClone(operations),next={...balance},s=new Set(spent),c=new Set(claimed),hld=new Map(holds),leaves=[],verified=new Set();
   for(const op of ops){
    if(op.kind==='debit'){
     check(exact(op,['kind','proof']));const d=inspect(op.proof),i=d.proof.intent;check(d.source===shard&&!s.has(d.nonce)&&next[i.payer]>=i.amount);s.add(d.nonce);next[i.payer]-=i.amount;
     if(d.destination===shard){next[i.payee]+=i.amount;check(integer(next[i.payee]));}
    }else if(reservationsEnabled&&op.kind==='reserve'){
     check(exact(op,['kind','proof']));const d=inspect(op.proof),i=d.proof.intent;
     check(d.source===shard&&!s.has(d.nonce)&&!hld.has(d.id)&&hld.size<MAX&&next[i.payer]>=i.amount);
     s.add(d.nonce);next[i.payer]-=i.amount;hld.set(d.id,d.proof);
    }else if(reservationsEnabled&&op.kind==='capture'){
     check(exact(op,['kind','proof','approval']));const d=inspect(op.proof),i=d.proof.intent;
     check(d.source===shard&&hld.has(d.id)&&JSON.stringify(hld.get(d.id))===JSON.stringify(d.proof));
     checkApproval(d,op.approval);hld.delete(d.id);
     if(d.destination===shard){next[i.payee]+=i.amount;check(integer(next[i.payee]));}
    }else if(reservationsEnabled&&op.kind==='cancel'){
     check(exact(op,['kind','proof','signature','pqSignature']));
     const d=inspect(op.proof),i=d.proof.intent,w=wallets.get(i.payer);
     check(d.source===shard&&hld.has(d.id)&&JSON.stringify(hld.get(d.id))===JSON.stringify(d.proof));
     const msg=cancelBytes(d);
     check(verify('sha256',msg,{key:w.cl,dsaEncoding:'ieee-p1363'},sig(op.signature,64))&&verify(null,msg,w.pq,sig(op.pqSignature,3309)));
     hld.delete(d.id);next[i.payer]+=i.amount;check(integer(next[i.payer]));
    }else{check(op.kind==='claim'&&exact(op,['kind','receipt']));const d=verifyDebitInternal(op.receipt,verified),i=d.proof.intent;check(d.destination===shard&&!c.has(d.id));c.add(d.id);next[i.payee]+=i.amount;check(integer(next[i.payee]));}
    leaves.push(opHash(op));
   }
   const h={network,shard,height:height+1,previous:root,operationsRoot:hash(['quantic-shard-operations/v1',ops.length,merkle(leaves)]),stateRoot:stateRoot(next,s,c,hld)};
   return {h,v:value(h),ops,next,s,c,hld,leaves};
  }
  function currentRound(){if(!active)active=round(shard,height+1,root);return active;}
  function finalize(operations,certificate){
   const p=propose(operations);check(currentRound().finalized(certificate).value===p.v);
   const receipts=[];for(let i=0;i<p.ops.length;i++){
    const o=p.ops[i];if(o.kind!=='debit'&&o.kind!=='capture')continue;const d=inspect(o.proof);if(d.destination===shard)continue;
    let a=p.leaves,j=i;const siblings=[];while(a.length>1){siblings.push(a[j^1]??a[j]);const b=[];for(let k=0;k<a.length;k+=2)b.push(hash(['quantic-shard-node/v1',a[k],a[k+1]??a[k]]));a=b;j=Math.floor(j/2);}
    receipts.push(o.kind==='capture'?{kind:'capture',header:structuredClone(p.h),certificate:structuredClone(certificate),proof:structuredClone(o.proof),approval:structuredClone(o.approval),index:i,count:p.ops.length,siblings}:{header:structuredClone(p.h),certificate:structuredClone(certificate),proof:structuredClone(o.proof),index:i,count:p.ops.length,siblings});
   }
   height++;root=p.v;balance=p.next;spent=p.s;claimed=p.c;holds=p.hld;lastHeader=structuredClone(p.h);lastCertificate=structuredClone(certificate);active=null;return receipts;
  }
  const authorities=new Map();
  const anchor=()=>({network,shard,height,root});
  function checkpoint(){check(lastHeader&&lastCertificate);return {header:structuredClone(lastHeader),certificate:structuredClone(lastCertificate),balances:{...balance},spent:[...spent].sort(),claimed:[...claimed].sort(),...(reservationsEnabled?{holds:structuredClone(heldEntries(holds))}:{}),simulationOnly:true,realPaymentAuthorized:false};}
  return Object.freeze({snapshot:()=>({height,root,balances:{...balance},spent:spent.size,claimed:claimed.size,...(reservationsEnabled?{reserved:holds.size,reservedCents:[...holds.values()].reduce((n,p)=>n+p.intent.amount,0)}:{})}),
   checkpoint,
   freezeForHandoff(){check(rotationEnabled&&!observerOnly&&!frozen&&height>0&&height<MAX&&![...authorities.values()].includes(height));frozen=true;active=null;return {anchor:anchor(),checkpoint:checkpoint()};},
   draftHandoff(nextMembers){check(rotationEnabled&&frozen);return handoffs.get(shard).draft(anchor(),nextMembers);},
   handoffOutgoingBytes(proposal){check(rotationEnabled&&frozen);return handoffs.get(shard).outgoingBytes(proposal,anchor());},
   handoffIncomingBytes(proposal,outgoing){check(rotationEnabled&&frozen);return handoffs.get(shard).incomingBytes(proposal,anchor(),outgoing);},
   activateHandoff(record){check(rotationEnabled&&frozen);const result=installHandoff(shard,record,checkpoint(),anchor());active=null;frozen=false;return result;},
   proposal(ops){const p=propose(ops);return {header:p.h,value:p.v,scope:currentRound().scope};},
   openAuthority(credentials){check(!observerOnly&&!frozen);check(!authorities.has(credentials.authorityPin)||authorities.get(credentials.authorityPin)!==height);const h=height,a=currentRound().openAuthority(credentials);authorities.set(credentials.authorityPin,h);
    return Object.freeze({prepare(ops){check(!frozen&&height===h);return a.prepare({round:0,value:propose(ops).v});},commit(qc){check(!frozen&&height===h);return a.commit(qc);}});
   },finalize});
 }
 return Object.freeze({network,intentBytes,openShard,verifyDebit,verifyCheckpoint,
  // A remote observer requires an externally trusted fresh anchor, not a
  // self-asserted root supplied by the sender. Import before opening source.
  importHandoff(record,checkpoint,anchor){check(rotationEnabled&&anchor&&!opened.has(anchor.shard));return installHandoff(anchor.shard,record,checkpoint,anchor);},
  committeeHistory(shard){check(rotationEnabled&&histories.has(shard));return structuredClone(histories.get(shard));},
  // A caller may sign a cancellation only with the same wallet's independent
  // hybrid keys. No unsigned unilateral refund and no automatic expiry.
  cancelBytes(proof){check(reservationsEnabled);return cancelBytes(inspect(proof));},
  reservedProof(checkpoint,anchor,reservationId){
   check(reservationsEnabled&&hex(reservationId));verifyCheckpoint(checkpoint,anchor);
   const entry=checkpoint.holds.find(([id])=>id===reservationId);check(entry);
   return structuredClone(entry[1]);
  }
 });
}
