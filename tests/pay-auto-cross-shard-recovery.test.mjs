import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync,randomBytes,sign} from 'node:crypto';
import {mkdtempSync,realpathSync,rmSync,readFileSync,writeFileSync} from 'node:fs';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {setTimeout as sleep} from 'node:timers/promises';
import {openShardedPayLab} from '../lib/quantic/pay-sharded-lab.mjs';
import {openDurableShard} from '../lib/quantic/pay-sharded-durable-lab.mjs';
import {openShardWitnessBridgeLab} from '../lib/quantic/pay-shard-witness-bridge-lab.mjs';
import {openCrossShardRecoveryWorkerLab} from '../lib/quantic/pay-cross-shard-recovery-worker-lab.mjs';
const hash=x=>createHash('sha256').update(JSON.stringify(x)).digest('hex');
const sha=b=>createHash('sha256').update(b).digest('hex');
function key(type='ed25519'){
 const cl=type==='ec'?generateKeyPairSync('ec',{namedCurve:'prime256v1'}):generateKeyPairSync(type),pq=generateKeyPairSync('ml-dsa-65');
 const a=cl.publicKey.export({type:'spki',format:'der'}),b=pq.publicKey.export({type:'spki',format:'der'});
 return {cl,pq,pub:{pin:sha(a),pqPin:sha(b),publicKey:a.toString('base64url'),pqPublicKey:b.toString('base64url')}};
}
const creds=k=>({authorityPin:k.pub.pin,classicalPrivateKey:k.cl.privateKey,pqPrivateKey:k.pq.privateKey});
test('automatic cross-shard recovery resumes after outage; three fresh witnesses refuse rolled-back ledger',{skip:process.platform!=='linux',timeout:150000},async t=>{
 const root=realpathSync(mkdtempSync(join(tmpdir(),'quantic-auto-settlement-'))),nodes=[],witnesses=[],voters=[];
 let sdb=null,ddb=null,worker=null;
 try{
  const east='demo-east',west='demo-west',aKeys=Array.from({length:16},()=>key()),bKeys=Array.from({length:16},()=>key()),wa=Array.from({length:4},()=>key()),wb=Array.from({length:4},()=>key()),alice=key('ec'),bob=key('ec');
  const config={shards:[{id:east,authorities:aKeys.map(k=>k.pub)},{id:west,authorities:bKeys.map(k=>k.pub)}],wallets:[{id:'demo-alice',shard:east,initial:1000,publicKey:alice.pub.publicKey,pqPublicKey:alice.pub.pqPublicKey},{id:'demo-shop',shard:west,initial:0,publicKey:bob.pub.publicKey,pqPublicKey:bob.pub.pqPublicKey}]};
  const mode={reservationsEnabled:true,crossShardAtomicEnabled:true,inboundPreparationEnabled:true};
  const ledger=openShardedPayLab(config,mode),source=ledger.openShard(east),dest=ledger.openShard(west);
  const bridgeA=openShardWitnessBridgeLab({config,options:mode,shard:east,witnesses:wa.map(k=>k.pub)}),bridgeB=openShardWitnessBridgeLab({config,options:mode,shard:west,witnesses:wb.map(k=>k.pub)});
  const sourceWitnesses=wa.map((k,i)=>bridgeA.openWitness({directory:join(root,'wa-'+i),credentials:{pin:k.pub.pin,classicalPrivateKey:k.cl.privateKey,pqPrivateKey:k.pq.privateKey},createNew:true}));
  const destWitnesses=wb.map((k,i)=>bridgeB.openWitness({directory:join(root,'wb-'+i),credentials:{pin:k.pub.pin,classicalPrivateKey:k.cl.privateKey,pqPrivateKey:k.pq.privateKey},createNew:true}));
  witnesses.push(...sourceWitnesses,...destWitnesses);
  function openDb(shard,createNew=false){return openDurableShard({config,shard,directory:join(root,'db-'+shard),createNew,...mode});}
  sdb=openDb(east,true);ddb=openDb(west,true);
  function commit(shard,db,ops,keys){
   const p=shard.proposal(ops),vs=keys.slice(0,11).map(k=>shard.openAuthority(creds(k)));
   const prepared={scope:p.scope,round:0,value:p.value,votes:vs.map(v=>v.prepare(ops))};
   const certificate={prepared,commit:{scope:p.scope,round:0,value:p.value,votes:vs.map(v=>v.commit(prepared))}};
   const receipts=shard.finalize(ops,certificate);
   assert.deepEqual(db.finalize(ops,certificate),receipts);
   return receipts;
  }
  function proof(amount){const intent={network:ledger.network,payer:'demo-alice',payee:'demo-shop',amount,nonce:randomBytes(32).toString('hex')},b=ledger.intentBytes(intent);
   return {intent,signature:sign('sha256',b,{key:alice.cl.privateKey,dsaEncoding:'ieee-p1363'}).toString('base64url'),pqSignature:sign(null,b,alice.pq.privateKey).toString('base64url')};}
  function anchor(db,shard){const s=db.snapshot();return {network:ledger.network,shard,height:s.height,root:s.root};}
  function approval(p){const i=p.intent,issued=Date.now(),expires=issued+120000,spki=alice.cl.publicKey.export({type:'spki',format:'der'}),pq=alice.pq.publicKey.export({type:'spki',format:'der'}),jwk=alice.cl.publicKey.export({format:'jwk'}),point=Buffer.concat([Buffer.from([4]),Buffer.from(jwk.x,'base64url'),Buffer.from(jwk.y,'base64url')]),s=sha(spki),d=sha(pq),intent={Payee:i.payee,Cents:i.amount,Nonce:i.nonce,Issued:issued,Expires:expires},msg=Buffer.from(JSON.stringify(['quantic-pay-native-simulation/v1',s,d,i.payee,i.amount,'EUR',i.nonce,issued,expires,false]));
   return {intent,signingPin:s,pqPin:d,classicalSignature:sign('sha256',msg,{key:alice.cl.privateKey,dsaEncoding:'ieee-p1363'}).toString('base64url'),pqSignature:sign(null,msg,alice.pq.privateKey).toString('base64url'),classicalPublic:point.toString('base64url'),pqPublic:pq.toString('base64url'),realPaymentAuthorized:false};}
  function decision(proof,outcome,ready=null,tag){
   const lab=outcome==='commit'?ledger.preparedDecision(proof,ready):ledger.abortDecision(proof);
   const ns=aKeys.slice(0,11).map((k,i)=>lab.openAuthority({directory:join(root,'decision-'+tag+'-'+i),createNew:true,credentials:creds(k)}));voters.push(...ns);
   const prepared={scope:lab.scope,round:0,value:lab.value(outcome),votes:ns.map(n=>n.prepare(outcome))};
   return {outcome,certificate:{prepared,commit:{scope:lab.scope,round:0,value:lab.value(outcome),votes:ns.map(n=>n.commit(outcome,prepared))}},...(ready?{ready}:{})};
  }
  const p=proof(600);
  commit(source,sdb,[{kind:'reserve',proof:p}],aKeys);
  bridgeA.synchronize(sdb,sourceWitnesses);
  const sourceProof={checkpoint:sdb.checkpoint(),anchor:anchor(sdb,east)};
  commit(dest,ddb,[{kind:'prepare-inbound',proof:p,sourceCheckpoint:sourceProof.checkpoint,sourceAnchor:sourceProof.anchor}],bKeys);
  bridgeB.synchronize(ddb,destWitnesses);
  const ready={checkpoint:ddb.checkpoint(),anchor:anchor(ddb,west)};
  const approved=decision(p,'commit',ready,'commit');
  commit(source,sdb,[{kind:'capture',proof:p,approval:approval(p),decision:approved}],aKeys);
  bridgeA.synchronize(sdb,sourceWitnesses);
  assert.equal(ddb.snapshot().balances['demo-shop'],0);
  for(let i=0;i<11;i++)nodes.push(openDurableShard({config,shard:west,directory:join(root,'validator-'+i),credentials:creds(bKeys[i]),createNew:true,...mode}));
  let online=false;
  const sourceFacade={snapshot:()=>sdb.snapshot(),certifiedCheckpoint:h=>sdb.certifiedCheckpoint(h),committedBlock:h=>sdb.committedBlock(h),recoverReceipts:h=>sdb.recoverReceipts(h),finalize:(ops,cert)=>sdb.finalize(ops,cert)};
  const destFacade={snapshot:()=>{if(!online)throw Error('destination network interrupted');return ddb.snapshot();},certifiedCheckpoint:h=>{if(!online)throw Error('destination network interrupted');return ddb.certifiedCheckpoint(h);},committedBlock:h=>{if(!online)throw Error('destination network interrupted');return ddb.committedBlock(h);},checkpoint:()=>{if(!online)throw Error('destination network interrupted');return ddb.checkpoint();},proposal:ops=>{if(!online)throw Error('destination network interrupted');return ddb.proposal(ops);},finalize:(ops,cert)=>{if(!online)throw Error('destination network interrupted');return ddb.finalize(ops,cert);}};
  worker=openCrossShardRecoveryWorkerLab({ledger,config,source:sourceFacade,destination:destFacade,sourceShard:east,destinationShard:west,sourceBridge:bridgeA,destinationBridge:bridgeB,sourceWitnesses,destinationWitnesses,destinationValidators:nodes,intervalMs:100});
  assert.equal(worker.start().status,'deferred');
  assert.equal(ddb.snapshot().balances['demo-shop'],0);
  online=true;
  for(let i=0;i<70&&ddb.snapshot().balances['demo-shop']!==600;i++)await sleep(100);
  assert.equal(ddb.snapshot().balances['demo-shop'],600,JSON.stringify(worker.last()));
  assert.equal(worker.runOnce().processed,0);
  assert.equal(ddb.snapshot().pendingInbound,0);
  assert.equal(worker.stats().claimed,1);
  worker.stop();
  const latestSource=Buffer.from(readFileSync(join(root,'db-'+east,'shard.sqlite')));
  // Further ABORT after a second, separately certified reservation.
  const q=proof(400),rv=[{kind:'reserve',proof:q}];
  commit(source,sdb,rv,aKeys);bridgeA.synchronize(sdb,sourceWitnesses);
  // The target in-memory chain missed the worker's credit. Replay its durable
  // blocks in a fresh full validator before preparing another inbound entry.
  const rebuilt=openShardedPayLab(config,mode).openShard(west);
  for(let h=1;h<=ddb.snapshot().height;h++){const b=ddb.committedBlock(h);rebuilt.finalize(b.operations,b.certificate);}
  const sourceReady={checkpoint:sdb.checkpoint(),anchor:anchor(sdb,east)};
  commit(rebuilt,ddb,[{kind:'prepare-inbound',proof:q,sourceCheckpoint:sourceReady.checkpoint,sourceAnchor:sourceReady.anchor}],bKeys);
  bridgeB.synchronize(ddb,destWitnesses);
  const abort=decision(q,'abort',null,'abort');
  commit(source,sdb,[{kind:'cancel',proof:q,decision:abort}],aKeys);bridgeA.synchronize(sdb,sourceWitnesses);
  assert.equal(ddb.snapshot().pendingInbound,1);
  assert.equal(worker.runOnce().status,'caught-up');
  assert.equal(ddb.snapshot().pendingInbound,0);
  assert.equal(worker.stats().released,1);
  assert.equal(ddb.snapshot().balances['demo-shop'],600);
  assert.equal(sdb.snapshot().balances['demo-alice'],400);
  // A fully rolled-back source replica must not pass the separately signed
  // witness state. Restoring the correct DB allows recovery without recredit.
  const currentSource=Buffer.from(readFileSync(join(root,'db-'+east,'shard.sqlite')));
  sdb.close();writeFileSync(join(root,'db-'+east,'shard.sqlite'),latestSource);sdb=openDb(east);
  const before=ddb.snapshot().height;
  assert.equal(worker.runOnce().status,'deferred');
  assert.equal(ddb.snapshot().height,before);
  sdb.close();writeFileSync(join(root,'db-'+east,'shard.sqlite'),currentSource);sdb=openDb(east);
  assert.equal(worker.runOnce().status,'caught-up');
  assert.equal(worker.stats().claimed,1);
  assert.equal(ddb.snapshot().balances['demo-shop']+sdb.snapshot().balances['demo-alice'],1000);
  t.diagnostic('AUTO_CROSS_SHARD_RECOVERY_V1 '+JSON.stringify({outageRetried:true,committedAndCredited:600,abortedAndReleased:400,rolledBackSourceRefused:true,postRecoveryHeight:ddb.snapshot().height,duplicateCredits:0,simulationOnly:true}));
 }finally{worker?.close();for(const v of [...nodes,...voters,...witnesses])try{v.close();}catch{}try{sdb?.close();}catch{}try{ddb?.close();}catch{}rmSync(root,{recursive:true,force:true});}
});
