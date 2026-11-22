// Laboratory adapter: certified shard state => independent signed witness
// monotonic state. Requires four separately administered witness directories,
// private signing keys and a live 3-of-4 consensus at each new height.
// Never substitute this for a real remote attestation service or stable TPM.
import {createHash,randomBytes} from 'node:crypto';
import {openShardedPayLab} from './pay-sharded-lab.mjs';
import {openQuorumFenceLab} from './pay-quorum-fence-lab.mjs';
const check=v=>{if(!v)throw Error('Shard witness bridge refused');};
const hex=v=>typeof v==='string'&&/^[a-f0-9]{64}$/.test(v);
const hash=v=>createHash('sha256').update(JSON.stringify(v)).digest('hex');
const ZERO='0'.repeat(64);
export function openShardWitnessBridgeLab({config,options,shard,witnesses}){
 const cfg=structuredClone(config),opts=structuredClone(options),ledger=openShardedPayLab(cfg,opts);
 const roster=cfg.shards.find(s=>s.id===shard)?.authorities;
 check(Array.isArray(roster)&&roster.length===16&&Array.isArray(witnesses)&&witnesses.length===4);
 const committee=hash(['quantic-shard-witness-committee/lab/v1',roster.map(x=>[x.pin,x.pqPin]).sort()]);
 const genesis=ledger.openShard(shard).snapshot().root;
 const quorum=openQuorumFenceLab({network:ledger.network,shard,initialCommittee:committee,genesisRoot:genesis,witnesses});
 function status(height,root){return {epoch:0,height,root,committee,tip:ZERO};}
 function verifyDecision(request,proof){
  check(request?.mode==='vote'&&proof&&Object.keys(proof).length===1&&proof.checkpoint);
  const cp=proof.checkpoint,h=cp.header,a=request.anchor;
  check(h?.network===ledger.network&&h.shard===shard&&h.previous===a.root&&h.height===a.height+1&&h.height<=256);
  check(a.epoch===0&&a.committee===committee&&a.tip===ZERO);
  ledger.verifyCheckpoint(cp,{network:ledger.network,shard,height:h.height,root:request.value});
  return {value:request.value};
 }
 function openWitness({directory,credentials,createNew=false}){
  return quorum.openWitness({directory,credentials,createNew,verifyDecision});
 }
 function fresh(expected,clients){
  check(Array.isArray(clients)&&clients.length>=3&&clients.length<=4&&expected&&Number.isSafeInteger(expected.height)&&expected.height>=0&&expected.height<=256&&hex(expected.root));
  const challenge=randomBytes(32).toString('hex'),attestations=[];
  for(const c of clients)try{attestations.push(c.attestState(challenge));}catch{}
  return quorum.verifyFreshState(challenge,attestations,status(expected.height,expected.root));
 }
 function publishCheckpoint(checkpoint,clients){
  check(Array.isArray(clients)&&clients.length>=3&&clients.length<=4);
  const h=checkpoint?.header;
  check(h?.network===ledger.network&&h.shard===shard&&h.height>=1&&h.height<=256);
  const root=hash(['quantic-shard-block/v1',h.network,h.shard,h.height,h.previous,h.operationsRoot,h.stateRoot]);
  ledger.verifyCheckpoint(checkpoint,{network:ledger.network,shard,height:h.height,root});
  try{return fresh({height:h.height,root},clients);}catch{}
  const prior=status(h.height-1,h.previous),request={anchor:prior,mode:'vote',value:root},grantable=[];
  for(const c of clients)try{
   const s=c.status();if(s.epoch===0&&s.height===prior.height&&s.root===prior.root&&s.committee===committee&&s.tip===ZERO)grantable.push(c);
  }catch{}
  check(grantable.length>=3);
  const grants=grantable.map(c=>c.grant(request));
  // The ledger certificate is checked independently inside each witness.
  let done=0;
  for(const c of grantable)try{c.complete(request,grants,{checkpoint});done++;}catch{}
  check(done>=3);
  return fresh({height:h.height,root},clients);
 }
 function checkpointRoot(checkpoint){
  const h=checkpoint?.header;
  check(h?.network===ledger.network&&h.shard===shard&&Number.isSafeInteger(h.height)
    &&h.height>=1&&h.height<=256);
  const value=hash(['quantic-shard-block/v1',h.network,h.shard,h.height,
   h.previous,h.operationsRoot,h.stateRoot]);
  ledger.verifyCheckpoint(checkpoint,{network:ledger.network,shard,height:h.height,root:value});
  return value;
 }
 // Repair a *single* lagging witness only from its own certified prefix.
 // It validates all intervening blocks and obtains a new 3/4 signed tip
 // ATTESTATION inside the witness prior to advancing any stored height.
 function repairWitness(replica,witness,peers){
  check(replica&&typeof replica.snapshot==='function'&&typeof replica.certifiedCheckpoint==='function');
  check(witness&&typeof witness.status==='function'&&typeof witness.catchUp==='function');
  check(Array.isArray(peers)&&peers.length>=3&&peers.length<=4
    &&peers.every(p=>p!==witness));
  const head=replica.snapshot(),local=witness.status();
  check(Number.isSafeInteger(head.height)&&head.height>=0&&head.height<=256&&hex(head.root));
  check(local.mode==='idle'&&local.pending===null&&local.epoch===0
    &&local.committee===committee&&local.tip===ZERO
    &&local.height<=head.height);
  if(local.height===head.height){
   check(local.root===head.root);
   fresh(head,[witness,...peers].slice(0,4));
   return Object.freeze({repaired:false,height:head.height,verifiedSteps:0,simulationOnly:true});
  }
  const priorRoot=local.height===0?genesis:checkpointRoot(replica.certifiedCheckpoint(local.height));
  check(local.root===priorRoot);
  const steps=[];
  let previous=priorRoot;
  for(let height=local.height+1;height<=head.height;height++){
   const checkpoint=replica.certifiedCheckpoint(height),h=checkpoint.header;
   const value=checkpointRoot(checkpoint);
   check(h.height===height&&h.previous===previous);
   steps.push({request:{anchor:status(height-1,previous),mode:'vote',value},
    proof:{checkpoint}});
   previous=value;
  }
  check(previous===head.root);
  const target=status(head.height,head.root);
  const updated=witness.catchUp({target,steps,peers});
  check(updated.height===head.height&&updated.root===head.root
    &&updated.verifiedSteps===steps.length);
  return Object.freeze({repaired:true,height:head.height,verifiedSteps:steps.length,simulationOnly:true});
 }
 // Never let an optional repair weaken the security quorum: first establish
 // a fresh 3/4 tip, then isolate and repair each lagging witness independently.
 function repairLagging(replica,clients){
  check(Array.isArray(clients)&&clients.length===4);
  const target=replica.snapshot();
  const initial=fresh(target,clients),result=[];
  for(let i=0;i<clients.length;i++){
   const witness=clients[i];
   let s;
   try{s=witness.status();}catch{result.push({index:i,status:'unavailable'});continue;}
   if(s.epoch===0&&s.height===target.height&&s.root===target.root
     &&s.committee===committee&&s.tip===ZERO&&s.mode==='idle'){
    result.push({index:i,status:'current'});continue;
   }
   try{
    const outcome=repairWitness(replica,witness,clients.filter((_,n)=>n!==i));
    result.push({index:i,status:outcome.repaired?'repaired':'current'});
   }catch(e){result.push({index:i,status:'blocked'});}
  }
  const after=fresh(target,clients);
  check(after.witnesses>=initial.witnesses);
  return Object.freeze({height:target.height,quorum:after.witnesses,
    repaired:result.filter(r=>r.status==='repaired').length,
    blocked:result.filter(r=>r.status==='blocked'||r.status==='unavailable').length,
    witnesses:result,simulationOnly:true});
 }
 function synchronize(replica,clients){
  check(replica&&typeof replica.snapshot==='function'&&typeof replica.certifiedCheckpoint==='function');
  const target=replica.snapshot();
  check(Number.isSafeInteger(target.height)&&target.height>=0&&target.height<=256&&hex(target.root));
  // Earlier blocks may already be advanced by 3 witnesses. Those witnesses
  // do not sign old heights again. The remaining stale nodes are excluded.
  for(let height=1;height<=target.height;height++){
   const cp=replica.certifiedCheckpoint(height),h=cp.header;
   const targetRoot=hash(['quantic-shard-block/v1',h.network,h.shard,h.height,h.previous,h.operationsRoot,h.stateRoot]);
   try{fresh({height,root:targetRoot},clients);continue;}catch{}
   // At intermediate heights a quorum may be further ahead. Skip only
   // when 3 stateful witnesses are already *beyond* this verified chain.
   const atLeast=clients.filter(c=>{try{
    const s=c.status();return s.epoch===0&&s.committee===committee&&s.tip===ZERO&&s.height>height;
   }catch{return false;}}).length;
   if(atLeast>=3)continue;
   publishCheckpoint(cp,clients);
  }
  return fresh(target,clients);
 }
 return Object.freeze({network:ledger.network,shard,genesis,committee,scope:quorum.scope,
  openWitness,fresh,publishCheckpoint,synchronize,repairWitness,repairLagging,simulationOnly:true});
}
