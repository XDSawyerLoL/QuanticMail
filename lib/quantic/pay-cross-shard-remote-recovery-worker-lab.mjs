// Laboratory async settlement worker, using independently running mTLS
// witness processes. Source/destination *ledgers* and the 11 destination
// validator vote journals are deliberately local to the trusted controller;
// their remote network custody is NOT implemented by this adapter.
// No automatic COMMIT decisions, real payment permissions, or live money.
import {createHash} from 'node:crypto';
import {performance} from 'node:perf_hooks';
const check=v=>{if(!v)throw Error('Remote cross-shard recovery lab refused');};
const hash=v=>createHash('sha256').update(JSON.stringify(v)).digest('hex');
const hex=v=>typeof v==='string'&&/^[a-f0-9]{64}$/.test(v);
const int=x=>Number.isSafeInteger(x)&&x>=0&&x<=256;
export function openRemoteCrossShardRecoveryWorkerLab({
 ledger,config,source,destination,sourceShard,destinationShard,
 sourceBridge,destinationBridge,destinationValidators,intervalMs=1000
}){
 check(ledger?.network&&typeof ledger.verifyDebit==='function'&&typeof ledger.intentBytes==='function');
 check(sourceShard!==destinationShard&&Array.isArray(destinationValidators)
  &&destinationValidators.length>=11&&destinationValidators.length<=16);
 const route=new Map(config?.wallets?.map(w=>[w.id,w.shard]));
 check(route.size===config.wallets.length&&route.size>=2);
 for(const replica of [source,destination,...destinationValidators])
  check(replica&&['snapshot','finalize'].every(k=>typeof replica[k]==='function'));
 for(const bridge of [sourceBridge,destinationBridge])
  check(bridge?.network===ledger.network&&typeof bridge.synchronize==='function'
   &&typeof bridge.fresh==='function'&&typeof bridge.repairLagging==='function');
 check(sourceBridge.shard===sourceShard&&destinationBridge.shard===destinationShard);
 check(int(intervalMs)&&intervalMs>=100&&intervalMs<=60000);
 let timer=null,closed=false,inFlight=null,last=null,attempts=0,
  claimed=0,released=0,deferred=0,consecutiveFailures=0,nextAttemptAt=0;
 async function tip(replica,bridge){
  const snapshot=replica.snapshot();
  check(int(snapshot.height)&&hex(snapshot.root));
  const cert=await bridge.synchronize(replica);
  check(cert.height===snapshot.height&&cert.root===snapshot.root&&cert.witnesses>=3);
  // Healing one lagging peer is optional, but must never weaken the 3/4 QC.
  const repaired=await bridge.repairLagging(replica);
  check(repaired.height===snapshot.height&&repaired.quorum>=3);
  return snapshot;
 }
 function syncValidator(validator){
  const latest=destination.snapshot(),before=validator.snapshot();
  check(int(before.height)&&int(latest.height)&&before.height<=latest.height);
  for(let h=before.height+1;h<=latest.height;h++){
   const b=destination.committedBlock(h);
   validator.finalize(b.operations,b.certificate);
  }
  const after=validator.snapshot();
  check(after.height===latest.height&&after.root===latest.root);
 }
 function stateOf(id){
  const state=destination.snapshot();
  if(state.height===0)return 'unprepared';
  const cp=destination.checkpoint();
  ledger.verifyCheckpoint(cp,{network:ledger.network,shard:destinationShard,
   height:state.height,root:state.root});
  if(cp.claimed.includes(id))return 'claimed';
  return cp.incoming.some(([entry])=>entry===id)?'prepared':'unprepared';
 }
 function transferId(proof){
  return hash(['quantic-shard-id/v1',ledger.intentBytes(proof.intent).toString('hex')]);
 }
 async function settle(op,receipt){
  const claim=op.kind==='capture',id=transferId(op.proof),state=stateOf(id);
  if(claim&&state==='claimed')return 'already-claimed';
  if(state!=='prepared')return 'not-prepared';
  const operations=[claim?{kind:'claim',receipt}:
   {kind:'release-inbound',proof:op.proof,decision:op.decision}];
  const proposal=destination.proposal(operations);
  for(const validator of destinationValidators)syncValidator(validator);
  const ready=[],votes=[];
  for(const validator of destinationValidators)try{
   votes.push(validator.prepare(operations));ready.push(validator);
  }catch{}
  check(votes.length>=11);
  const prepared={scope:proposal.scope,round:0,value:proposal.value,votes};
  const commits=[];
  for(const validator of ready)try{commits.push(validator.commit(prepared));}catch{}
  check(commits.length>=11);
  destination.finalize(operations,{
   prepared,commit:{scope:proposal.scope,round:0,value:proposal.value,votes:commits}
  });
  // The receiver persists the QC BEFORE acknowledgement; if its witness
  // quorum fails, the next attempt replays exactly this durable block.
  await tip(destination,destinationBridge);
  for(const validator of destinationValidators)syncValidator(validator);
  return claim?'claimed':'released';
 }
 async function scan(){
  check(!closed);attempts++;
  const src=await tip(source,sourceBridge);
  await tip(destination,destinationBridge);
  let processed=0,seen=0,skipped=0;
  for(let h=1;h<=src.height;h++){
   const block=source.committedBlock(h),receipts=source.recoverReceipts(h);
   const available=new Map();
   for(const receipt of receipts){
    const d=ledger.verifyDebit(receipt);
    if(d.source!==sourceShard||d.destination!==destinationShard)continue;
    check(receipt.kind==='capture'&&receipt.decision?.outcome==='commit'
     &&!available.has(d.id));
    available.set(d.id,receipt);
   }
   for(const op of block.operations){
    if(op.kind!=='capture'&&op.kind!=='cancel')continue;
    check(op.proof?.intent?.network===ledger.network);
    const i=op.proof.intent,id=transferId(op.proof);
    const receipt=op.kind==='capture'?available.get(id):null;
    if(receipt){check(JSON.stringify(receipt.proof)===JSON.stringify(op.proof));available.delete(id);}
    if(op.kind==='capture')check(receipt&&op.decision?.outcome==='commit');
    else check(op.decision?.outcome==='abort');
    check(route.get(i.payer)===sourceShard);
    if(route.get(i.payee)!==destinationShard)continue;
    seen++;
    const result=await settle(op,receipt);
    if(result==='claimed'){claimed++;processed++;}
    else if(result==='released'){released++;processed++;}
    else skipped++;
   }
   check(available.size===0);
  }
  return Object.freeze({status:'caught-up',seen,processed,skipped,
   sourceHeight:src.height,destinationHeight:destination.snapshot().height,
   claims:claimed,releases:released,simulationOnly:true});
 }
 async function tick(automatic=false){
  if(closed)return Object.freeze({status:'stopped',simulationOnly:true});
  if(inFlight)return inFlight; // never race concurrent votes or attestations
  // Monotonic backoff avoids hammering offline peers during an extended
  // partition. Explicit runOnce still forces a fresh, quorum-gated check.
  if(automatic&&performance.now()<nextAttemptAt)return last;
  inFlight=(async()=>{
   try{
    const result=await scan();
    consecutiveFailures=0;nextAttemptAt=0;
    return last=result;
   }catch(e){
    deferred++;consecutiveFailures++;
    const delay=Math.min(30000,intervalMs*2**Math.min(consecutiveFailures,10));
    nextAttemptAt=performance.now()+delay;
    return last=Object.freeze({status:'deferred',
     reason:e instanceof Error?e.message:String(e),retryAfterMs:delay,
     simulationOnly:true});
   }
  })();
  try{return await inFlight;}finally{inFlight=null;}
 }
 async function start(){
  check(!closed&&timer===null);
  timer=setInterval(()=>{void tick(true);},intervalMs);
  return tick();
 }
 function stop(){if(timer!==null){clearInterval(timer);timer=null;}}
 async function close(){stop();closed=true;if(inFlight)await inFlight;}
 return Object.freeze({
  start,stop,runOnce:tick,last:()=>last,
  stats:()=>Object.freeze({attempts,claimed,released,deferred,consecutiveFailures,
   retryAfterMs:Math.max(0,Math.ceil(nextAttemptAt-performance.now())),
   running:timer!==null,simulationOnly:true}),close
 });
}
