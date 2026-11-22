import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync,randomBytes,sign} from 'node:crypto';
import {mkdtempSync,realpathSync,rmSync,readFileSync,writeFileSync} from 'node:fs';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {openShardedPayLab} from '../lib/quantic/pay-sharded-lab.mjs';
import {openDurableShard} from '../lib/quantic/pay-sharded-durable-lab.mjs';
import {openShardWitnessBridgeLab} from '../lib/quantic/pay-shard-witness-bridge-lab.mjs';
const sha=b=>createHash('sha256').update(b).digest('hex');
function key(type='ed25519'){
 const cl=type==='ec'?generateKeyPairSync('ec',{namedCurve:'prime256v1'}):generateKeyPairSync(type),pq=generateKeyPairSync('ml-dsa-65');
 const a=cl.publicKey.export({type:'spki',format:'der'}),b=pq.publicKey.export({type:'spki',format:'der'});
 return {cl,pq,pub:{pin:sha(a),pqPin:sha(b),publicKey:a.toString('base64url'),pqPublicKey:b.toString('base64url')}};
}
const creds=k=>({authorityPin:k.pub.pin,classicalPrivateKey:k.cl.privateKey,pqPrivateKey:k.pq.privateKey});
const anchor=s=>({epoch:s.epoch,height:s.height,root:s.root,committee:s.committee,tip:s.tip});
test('three current witnesses safely restore one rolled-back witness from certified checkpoint chain, never unlock a conflicting vote',{skip:process.platform!=='linux',timeout:90000},t=>{
 const root=realpathSync(mkdtempSync(join(tmpdir(),'quantic-witness-repair-'))),nodes=[];
 let db=null;
 try{
  const east='demo-east',west='demo-west',keys=Array.from({length:16},()=>key()),other=Array.from({length:16},()=>key()),wk=Array.from({length:4},()=>key()),alice=key('ec'),bob=key('ec');
  const cfg={shards:[{id:east,authorities:keys.map(k=>k.pub)},{id:west,authorities:other.map(k=>k.pub)}],wallets:[{id:'demo-alice',shard:east,initial:1000,publicKey:alice.pub.publicKey,pqPublicKey:alice.pub.pqPublicKey},{id:'demo-shop',shard:west,initial:0,publicKey:bob.pub.publicKey,pqPublicKey:bob.pub.pqPublicKey}]};
  const mode={reservationsEnabled:true},ledger=openShardedPayLab(cfg,mode),chain=ledger.openShard(east);
  db=openDurableShard({config:cfg,shard:east,directory:join(root,'ledger'),createNew:true,...mode});
  const bridge=openShardWitnessBridgeLab({config:cfg,options:mode,shard:east,witnesses:wk.map(k=>k.pub)});
  function open(i,createNew=false){
   const k=wk[i];const w=bridge.openWitness({directory:join(root,'w-'+i),createNew,credentials:{pin:k.pub.pin,classicalPrivateKey:k.cl.privateKey,pqPrivateKey:k.pq.privateKey}});
   nodes[i]=w;return w;
  }
  for(let i=0;i<4;i++)open(i,true);
  function block(amount){
   const intent={network:ledger.network,payer:'demo-alice',payee:'demo-shop',amount,nonce:randomBytes(32).toString('hex')};
   const bytes=ledger.intentBytes(intent),proof={intent,signature:sign('sha256',bytes,{key:alice.cl.privateKey,dsaEncoding:'ieee-p1363'}).toString('base64url'),pqSignature:sign(null,bytes,alice.pq.privateKey).toString('base64url')};
   const ops=[{kind:'reserve',proof}],candidate=chain.proposal(ops),validators=keys.slice(0,11).map(k=>chain.openAuthority(creds(k)));
   const prepared={scope:candidate.scope,round:0,value:candidate.value,votes:validators.map(v=>v.prepare(ops))};
   const qc={prepared,commit:{scope:candidate.scope,round:0,value:candidate.value,votes:validators.map(v=>v.commit(prepared))}};
   assert.deepEqual(db.finalize(ops,qc),chain.finalize(ops,qc));
   bridge.synchronize(db,nodes);
  }
  block(100);
  const backup=readFileSync(join(root,'w-0','fence.sqlite'));
  block(150);
  assert.equal(bridge.fresh(db.snapshot(),nodes).witnesses,4);
  nodes[0].close();writeFileSync(join(root,'w-0','fence.sqlite'),backup);open(0);
  assert.equal(nodes[0].status().height,1);
  assert.equal(bridge.fresh(db.snapshot(),nodes).witnesses,3);
  const original=nodes[0].status();
  const badReplica={
   snapshot:()=>db.snapshot(),
   certifiedCheckpoint:h=>{
    const cp=db.certifiedCheckpoint(h);
    if(h===2)cp.header.operationsRoot='f'.repeat(64);
    return cp;
   }
  };
  assert.throws(()=>bridge.repairWitness(badReplica,nodes[0],nodes.slice(1)));
  assert.deepEqual(nodes[0].status(),original);
  const oldChallenge=randomBytes(32).toString('hex'),oldSignatures=nodes.slice(1).map(x=>x.attestState(oldChallenge));
  const peers=nodes.slice(1).map((x,i)=>({attestState:()=>oldSignatures[i]}));
  assert.throws(()=>nodes[0].catchUp({
   target:anchor(nodes[1].status()),steps:[],peers
  }));
  assert.deepEqual(nodes[0].status(),original);
  const repaired=bridge.repairLagging(db,nodes);
  assert.equal(repaired.repaired,1);
  assert.equal(repaired.blocked,0);
  assert.equal(repaired.quorum,4);
  assert.equal(nodes[0].status().height,2);
  assert.equal(nodes[0].status().root,db.snapshot().root);
  assert.equal(bridge.repairLagging(db,nodes).repaired,0);
  block(200);
  assert.equal(bridge.fresh(db.snapshot(),nodes).witnesses,4);
  // Simulate a lagged, maliciously locked witness after another restart.
  nodes[0].close();writeFileSync(join(root,'w-0','fence.sqlite'),backup);open(0);
  const locked=nodes[0].status();
  nodes[0].grant({anchor:anchor(locked),mode:'vote',value:'f'.repeat(64)});
  assert.equal(nodes[0].status().mode,'vote');
  assert.throws(()=>bridge.repairWitness(db,nodes[0],nodes.slice(1)));
  const outcome=bridge.repairLagging(db,nodes);
  assert.equal(outcome.quorum,3);
  assert.equal(outcome.blocked,1);
  assert.equal(nodes[0].status().mode,'vote');
  assert.equal(nodes[0].status().height,1);
  assert.equal(bridge.fresh(db.snapshot(),nodes).witnesses,3);
  t.diagnostic('WITNESS_CERTIFIED_CATCHUP_V1 '+JSON.stringify({ledgerHeight:3,repairedOneRolledBackWitness:true,untrustedHistoryRefused:true,replayedAttestationRefused:true,pendingConflictLocked:true,healthyQuorum:3,simulationOnly:true}));
 }finally{for(const n of nodes)try{n.close();}catch{}try{db?.close();}catch{}rmSync(root,{recursive:true,force:true});}
});
