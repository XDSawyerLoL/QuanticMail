// Synthetic fixed-membership sharded ledger. In-memory, one state machine per
// shard, no real funds. Debit then certified claim, no unilateral refund.
// Pending credits may remain locked indefinitely. No atomic availability claim.
// Honest validators must maintain non-rollback state, one vote per height.
import {createHash,createPublicKey,verify} from 'node:crypto';
import {createPayRoundLab} from './pay-round-lab.mjs';
const check=v=>{if(!v)throw Error('Sharded Pay laboratory refused');};
const hash=v=>createHash('sha256').update(JSON.stringify(v)).digest('hex');
const hex=s=>typeof s==='string'&&/^[a-f0-9]{64}$/.test(s);
const id=s=>typeof s==='string'&&/^demo-[a-z0-9]{1,24}$/.test(s);
const integer=(n,max=Number.MAX_SAFE_INTEGER)=>Number.isSafeInteger(n)&&n>=0&&n<=max;
const exact=(o,ks)=>o&&typeof o==='object'&&!Array.isArray(o)&&Object.keys(o).length===ks.length&&ks.every(k=>Object.hasOwn(o,k));
const sig=(s,n)=>{check(typeof s==='string'&&s.length===Math.ceil(n*8/6)&&/^[A-Za-z0-9_-]+$/.test(s));const b=Buffer.from(s,'base64url');check(b.length===n&&b.toString('base64url')===s);return b;};
const key=(s,n,type)=>{const b=sig(s,n),k=createPublicKey({key:b,format:'der',type:'spki'});check(k.asymmetricKeyType===type&&k.export({format:'der',type:'spki'}).equals(b));if(type==='ec')check(k.asymmetricKeyDetails.namedCurve==='prime256v1');return k;};
const MAX=256, LIMIT=64;
export function openShardedPayLab(config){
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
 const network=hash(['quantic-shards/lab/v1',[...shards.values()].sort((a,b)=>a.id.localeCompare(b.id)).map(s=>[s.id,s.authorities.map(a=>[a.pin,a.pqPin]).sort()]),[...wallets.values()].sort((a,b)=>a.id.localeCompare(b.id)).map(w=>[w.id,w.shard,w.initial,w.publicKey,w.pqPublicKey])]);
 const genesis=s=>hash(['quantic-shard-genesis/v1',network,s]);
 const round=(s,height,previous)=>{check(shards.has(s)&&integer(height,MAX)&&height>=1&&hex(previous));return createPayRoundLab({network:hash(['quantic-shard-round/v1',network,s]),height,previousRoot:previous,authorities:shards.get(s).authorities,admissionRound:true,committeeMode:true});};
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
 const opHash=op=>op.kind==='debit'?hash(['quantic-shard-op/v1','debit',inspect(op.proof).proof]):hash(['quantic-shard-op/v1','claim',op.receipt]);
 const merkle=leaves=>{let a=leaves;while(a.length>1){const b=[];for(let i=0;i<a.length;i+=2)b.push(hash(['quantic-shard-node/v1',a[i],a[i+1]??a[i]]));a=b;}return a[0];};
 function verifyDebit(receipt){
  check(exact(receipt,['header','certificate','proof','index','count','siblings'])&&integer(receipt.count,LIMIT)&&receipt.count>=1&&integer(receipt.index,receipt.count-1)&&Array.isArray(receipt.siblings)&&receipt.siblings.length===Math.ceil(Math.log2(receipt.count)));
  const d=inspect(receipt.proof),h=receipt.header;check(d.source!==d.destination&&h.shard===d.source);
  check(round(h.shard,h.height,h.previous).finalized(receipt.certificate).value===value(h));
  let x=opHash({kind:'debit',proof:d.proof}),j=receipt.index,n=receipt.count;
  for(const sib of receipt.siblings){check(hex(sib));if((j^1)>=n)check(sib===x);x=j%2?hash(['quantic-shard-node/v1',sib,x]):hash(['quantic-shard-node/v1',x,sib]);j=Math.floor(j/2);n=Math.ceil(n/2);}
  check(hash(['quantic-shard-operations/v1',receipt.count,x])===h.operationsRoot);return d;
 }
 const opened=new Set();
 function openShard(shard){
  check(shards.has(shard)&&!opened.has(shard));opened.add(shard);let height=0,root=genesis(shard),balance=Object.fromEntries([...wallets.values()].filter(w=>w.shard===shard).map(w=>[w.id,w.initial])),spent=new Set(),claimed=new Set();
  let active=null;
  function propose(operations){
   check(Array.isArray(operations)&&operations.length>=1&&operations.length<=LIMIT&&height<MAX);
   const ops=structuredClone(operations),next={...balance},s=new Set(spent),c=new Set(claimed),leaves=[];
   for(const op of ops){
    if(op.kind==='debit'){
     check(exact(op,['kind','proof']));const d=inspect(op.proof),i=d.proof.intent;check(d.source===shard&&!s.has(d.nonce)&&next[i.payer]>=i.amount);s.add(d.nonce);next[i.payer]-=i.amount;
     if(d.destination===shard){next[i.payee]+=i.amount;check(integer(next[i.payee]));}
    }else{check(op.kind==='claim'&&exact(op,['kind','receipt']));const d=verifyDebit(op.receipt),i=d.proof.intent;check(d.destination===shard&&!c.has(d.id));c.add(d.id);next[i.payee]+=i.amount;check(integer(next[i.payee]));}
    leaves.push(opHash(op));
   }
   const h={network,shard,height:height+1,previous:root,operationsRoot:hash(['quantic-shard-operations/v1',ops.length,merkle(leaves)]),stateRoot:hash(['quantic-shard-state/v1',Object.entries(next).sort(),[...s].sort(),[...c].sort()])};
   return {h,v:value(h),ops,next,s,c,leaves};
  }
  function currentRound(){if(!active)active=round(shard,height+1,root);return active;}
  function finalize(operations,certificate){
   const p=propose(operations);check(currentRound().finalized(certificate).value===p.v);
   const receipts=[];for(let i=0;i<p.ops.length;i++){
    const o=p.ops[i];if(o.kind!=='debit')continue;const d=inspect(o.proof);if(d.destination===shard)continue;
    let a=p.leaves,j=i;const siblings=[];while(a.length>1){siblings.push(a[j^1]??a[j]);const b=[];for(let k=0;k<a.length;k+=2)b.push(hash(['quantic-shard-node/v1',a[k],a[k+1]??a[k]]));a=b;j=Math.floor(j/2);}
    receipts.push({header:structuredClone(p.h),certificate:structuredClone(certificate),proof:structuredClone(o.proof),index:i,count:p.ops.length,siblings});
   }
   height++;root=p.v;balance=p.next;spent=p.s;claimed=p.c;active=null;return receipts;
  }
  const authorities=new Map();
  return Object.freeze({snapshot:()=>({height,root,balances:{...balance},spent:spent.size,claimed:claimed.size}),proposal(ops){const p=propose(ops);return {header:p.h,value:p.v,scope:currentRound().scope};},
   openAuthority(credentials){check(!authorities.has(credentials.authorityPin)||authorities.get(credentials.authorityPin)!==height);const h=height,a=currentRound().openAuthority(credentials);authorities.set(credentials.authorityPin,h);
    return Object.freeze({prepare(ops){check(height===h);return a.prepare({round:0,value:propose(ops).v});},commit(qc){check(height===h);return a.commit(qc);}});
   },finalize});
 }
 return Object.freeze({network,intentBytes,openShard,verifyDebit});
}
