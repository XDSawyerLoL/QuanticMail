// In-process local poller for the experimental two-shard settlement engine.
// No network transport, remote orchestration, guaranteed availability,
// production money, or durable credential storage. Runs only while Node runs.
// Reconciles solely finalized source blocks; never infers COMMIT from timeout.
// Independent 3/4 hybrid witness freshness is required for BOTH shard tips.
import {createHash} from 'node:crypto';
const check=v=>{if(!v)throw Error('Cross-shard recovery worker refused');};
const hash=v=>createHash('sha256').update(JSON.stringify(v)).digest('hex');
const hex=x=>typeof x==='string'&&/^[a-f0-9]{64}$/.test(x);
const int=x=>Number.isSafeInteger(x)&&x>=0&&x<=256;
export function openCrossShardRecoveryWorkerLab({
 ledger,config,source,destination,sourceShard,destinationShard,
 sourceBridge,destinationBridge,sourceWitnesses,destinationWitnesses,
 destinationValidators,intervalMs=1000
}){
 check(ledger?.network&&typeof ledger.verifyDebit==='function'&&typeof ledger.intentBytes==='function');
 check(sourceShard!==destinationShard&&Array.isArray(destinationValidators)&&destinationValidators.length>=11&&destinationValidators.length<=16);
 check(Array.isArray(config?.wallets)&&config.wallets.length>=2);
 const walletShards=new Map(config.wallets.map(w=>[w.id,w.shard]));
 check(walletShards.size===config.wallets.length);
 check(Array.isArray(sourceWitnesses)&&sourceWitnesses.length>=3&&Array.isArray(destinationWitnesses)&&destinationWitnesses.length>=3);
 check(Number.isSafeInteger(intervalMs)&&intervalMs>=100&&intervalMs<=60000);
 for(const replica of [source,destination,...destinationValidators])
  check(replica&&typeof replica.snapshot==='function'&&typeof replica.finalize==='function');
 for(const bridge of [sourceBridge,destinationBridge])
  check(bridge?.network===ledger.network&&typeof bridge.synchronize==='function'&&typeof bridge.fresh==='function');
 check(sourceBridge.shard===sourceShard&&destinationBridge.shard===destinationShard);
 let closed=false,timer=null,last=null,attempts=0,claimed=0,released=0,deferred=0;
 function tip(replica,bridge,witnesses){
  const snapshot=replica.snapshot();
  check(int(snapshot.height)&&hex(snapshot.root));
  const certificate=bridge.synchronize(replica,witnesses);
  check(certificate.height===snapshot.height&&certificate.root===snapshot.root&&certificate.witnesses>=3);
  return snapshot;
 }
 function syncValidator(v){
  const dest=destination.snapshot(),local=v.snapshot();
  check(int(local.height)&&int(dest.height)&&local.height<=dest.height);
  for(let h=local.height+1;h<=dest.height;h++){
   const block=destination.committedBlock(h);
   v.finalize(block.operations,block.certificate);
  }
  const now=v.snapshot();
  check(now.height===dest.height&&now.root===dest.root);
 }
 function settledState(id){
  const h=destination.snapshot().height;
  if(!h)return 'unprepared';
  const cp=destination.checkpoint();
  ledger.verifyCheckpoint(cp,{network:ledger.network,shard:destinationShard,height:h,root:destination.snapshot().root});
  if(cp.claimed.includes(id))return 'claimed';
  return cp.incoming.some(e=>e[0]===id)?'prepared':'unprepared';
 }
 function idFromProof(p){
  const bytes=ledger.intentBytes(p.intent);
  return hash(['quantic-shard-id/v1',bytes.toString('hex')]);
 }
 function decide(op,receipt){
  const kind=op.kind==='capture'?'claim':'release-inbound';
  const id=idFromProof(op.proof),state=settledState(id);
  if(kind==='claim'&&state==='claimed')return 'already-claimed';
  if(state!=='prepared')return 'not-prepared';
  const operations=[kind==='claim'?{kind:'claim',receipt}:{kind:'release-inbound',proof:op.proof,decision:op.decision}];
  const p=destination.proposal(operations);
  for(const validator of destinationValidators)syncValidator(validator);
  const preparations=[],participants=[];
  for(const validator of destinationValidators)try{
   preparations.push(validator.prepare(operations));participants.push(validator);
  }catch{}
  check(preparations.length>=11);
  const prepared={scope:p.scope,round:0,value:p.value,votes:preparations};
  const commitVotes=[];
  for(const v of participants)try{commitVotes.push(v.commit(prepared));}catch{}
  check(commitVotes.length>=11);
  const certificate={prepared,commit:{scope:p.scope,round:0,value:p.value,votes:commitVotes}};
  // The observable ledger is updated only after a REAL valid 11/16 QC.
  destination.finalize(operations,certificate);
  // A crash here is safe: next tick first catches the witnesses up from
  // certified destination blocks, and never credits/refunds twice.
  tip(destination,destinationBridge,destinationWitnesses);
  for(const validator of destinationValidators)syncValidator(validator);
  return kind==='claim'?'claimed':'released';
 }
 function scan(){
  check(!closed);attempts++;
  const src=tip(source,sourceBridge,sourceWitnesses);
  tip(destination,destinationBridge,destinationWitnesses);
  let processed=0,skipped=0,seen=0;
  for(let h=1;h<=src.height;h++){
   const b=source.committedBlock(h);
   const receipts=source.recoverReceipts(h);
   const available=new Map();
   for(const receipt of receipts){
    const d=ledger.verifyDebit(receipt);
    if(d.source!==sourceShard||d.destination!==destinationShard)continue;
    check(receipt.kind==='capture'&&receipt.decision?.outcome==='commit');
    check(!available.has(d.id));available.set(d.id,receipt);
   }
   for(const op of b.operations){
    if(op.kind!=='capture'&&op.kind!=='cancel')continue;
    if(op.proof?.intent?.payer===undefined)throw Error('Missing committed source intent');
    const id=idFromProof(op.proof),i=op.proof.intent;
    if(i.network!==ledger.network||i.payee===i.payer)throw Error('Invalid committed intent');
    const receipt=op.kind==='capture'?available.get(id):null;
    if(op.kind==='capture'){
     check(receipt&&receipt.decision.outcome==='commit'&&JSON.stringify(receipt.proof)===JSON.stringify(op.proof));
     available.delete(id);
    }else check(op.decision?.outcome==='abort');
    // This worker only owns one specific source/destination pair.
    check(walletShards.get(i.payer)===sourceShard);
    if(walletShards.get(i.payee)!==destinationShard)continue;
    const result=decide(op,receipt);
    seen++;
    if(result==='claimed'){claimed++;processed++;}
    else if(result==='released'){released++;processed++;}
    else skipped++;
   }
   check(available.size===0);
  }
  return Object.freeze({status:'caught-up',seen,processed,skipped,claims:claimed,releases:released,
   sourceHeight:src.height,destinationHeight:destination.snapshot().height,simulationOnly:true});
 }
 function runOnce(){
  if(closed)return Object.freeze({status:'stopped',simulationOnly:true});
  try{last=scan();}
  catch(e){deferred++;last=Object.freeze({status:'deferred',reason:e instanceof Error?e.message:String(e),simulationOnly:true});}
  return last;
 }
 function start(){
  check(!closed&&timer===null);
  runOnce();
  timer=setInterval(runOnce,intervalMs);
  return last;
 }
 function stop(){if(timer!==null){clearInterval(timer);timer=null;}}
 return Object.freeze({
  start,stop,runOnce,last:()=>last,stats:()=>Object.freeze({attempts,claimed,released,deferred,running:timer!==null,simulationOnly:true}),
  close(){stop();closed=true;}
 });
}
