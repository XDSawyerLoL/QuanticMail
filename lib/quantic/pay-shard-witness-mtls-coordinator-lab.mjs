// Asynchronous mTLS bridge between a certified shard replica and four
// physically separate-capable witness processes. Requires 3/4 fresh
// Ed25519 + ML-DSA-65 attestations and independently certified vote grants.
// No synchronous local witness handles or remote private signing keys.
import {createHash,randomBytes} from 'node:crypto';
import {openShardedPayLab} from './pay-sharded-lab.mjs';
import {openQuorumFenceLab} from './pay-quorum-fence-lab.mjs';
const check=v=>{if(!v)throw Error('Remote shard witness quorum refused');};
const hash=v=>createHash('sha256').update(JSON.stringify(v)).digest('hex');
const hex=v=>typeof v==='string'&&/^[a-f0-9]{64}$/.test(v);
const ZERO='0'.repeat(64);
export function openRemoteShardWitnessCoordinatorLab({config,options,shard,witnesses,clients}){
 check(Array.isArray(witnesses)&&witnesses.length===4&&Array.isArray(clients)&&clients.length===4
  &&clients.every(c=>['status','attestState','grantCertified','complete'].every(m=>typeof c?.[m]==='function')));
 const ledger=openShardedPayLab(structuredClone(config),structuredClone(options));
 const authorities=config.shards.find(s=>s.id===shard)?.authorities;
 check(Array.isArray(authorities)&&authorities.length===16);
 const committee=hash(['quantic-shard-witness-committee/lab/v1',authorities.map(x=>[x.pin,x.pqPin]).sort()]);
 const genesis=ledger.openShard(shard).snapshot().root;
 const quorum=openQuorumFenceLab({network:ledger.network,shard,
  initialCommittee:committee,genesisRoot:genesis,witnesses});
 function expected(height,root){return {epoch:0,height,root,committee,tip:ZERO};}
 function checkpointRoot(cp){
  const h=cp?.header;
  check(h?.network===ledger.network&&h.shard===shard&&Number.isSafeInteger(h.height)
   &&h.height>=1&&h.height<=256);
  const root=hash(['quantic-shard-block/v1',h.network,h.shard,h.height,h.previous,
   h.operationsRoot,h.stateRoot]);
  ledger.verifyCheckpoint(cp,{network:ledger.network,shard,height:h.height,root});
  return root;
 }
 async function fresh(target){
  check(Number.isSafeInteger(target?.height)&&target.height>=0&&target.height<=256&&hex(target.root));
  const challenge=randomBytes(32).toString('hex');
  const replies=await Promise.allSettled(clients.map(c=>c.attestState(challenge)));
  const attestations=replies.filter(r=>r.status==='fulfilled').map(r=>r.value);
  return quorum.verifyFreshState(challenge,attestations,expected(target.height,target.root));
 }
 async function statuses(){
  const replies=await Promise.allSettled(clients.map(c=>c.status()));
  return replies.map(r=>r.status==='fulfilled'?r.value:null);
 }
 async function publishCheckpoint(cp){
  const h=cp?.header,root=checkpointRoot(cp);
  try{return await fresh({height:h.height,root});}catch{}
  const prior=expected(h.height-1,h.previous);
  const states=await statuses(),eligible=[];
  for(let i=0;i<4;i++){
   const s=states[i];
   if(s?.epoch===prior.epoch&&s.height===prior.height&&s.root===prior.root
      &&s.committee===prior.committee&&s.tip===prior.tip
      &&s.mode==='idle'&&s.pending===null)eligible.push(i);
  }
  check(eligible.length>=3);
  const request={anchor:prior,mode:'vote',value:root},proof={checkpoint:cp};
  const signed=await Promise.allSettled(eligible.map(i=>clients[i].grantCertified(request,proof)));
  const grants=signed.filter(r=>r.status==='fulfilled').map(r=>r.value);
  quorum.verifyGrants(request,grants);
  const committed=await Promise.allSettled(eligible.map(i=>clients[i].complete(request,grants,proof)));
  check(committed.filter(r=>r.status==='fulfilled').length>=3);
  return fresh({height:h.height,root});
 }
 async function synchronize(replica){
  check(replica&&typeof replica.snapshot==='function'
   &&typeof replica.certifiedCheckpoint==='function');
  const tip=replica.snapshot();
  check(Number.isSafeInteger(tip.height)&&tip.height>=0&&tip.height<=256&&hex(tip.root));
  // Reject forks: every checkpoint must chain to the previous certified root.
  let prior=genesis;
  for(let height=1;height<=tip.height;height++){
   const cp=replica.certifiedCheckpoint(height);
   check(cp.header.height===height&&cp.header.previous===prior);
   const root=checkpointRoot(cp);prior=root;
   try{await fresh({height,root});continue;}catch{}
   const s=await statuses();
   const ahead=s.filter(x=>x?.epoch===0&&x.height>height&&x.committee===committee
    &&x.tip===ZERO&&x.mode==='idle'&&x.pending===null).length;
   if(ahead>=3)continue;
   await publishCheckpoint(cp);
  }
  check(prior===tip.root);
  return fresh(tip);
 }
 return Object.freeze({network:ledger.network,shard,committee,scope:quorum.scope,
  genesis,fresh,statuses,publishCheckpoint,synchronize,simulationOnly:true});
}
