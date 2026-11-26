import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,randomBytes,createHash,sign} from 'node:crypto';
import {mkdtempSync,realpathSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {DatabaseSync} from 'node:sqlite';
import {openShardedPayLab} from '../lib/quantic/pay-sharded-lab.mjs';
import {openDurableShard} from '../lib/quantic/pay-sharded-durable-lab.mjs';
const hash=b=>createHash('sha256').update(b).digest('hex');
function pair(type){
 const a=type==='ec'?generateKeyPairSync('ec',{namedCurve:'prime256v1'}):generateKeyPairSync(type),b=generateKeyPairSync('ml-dsa-65');
 const x=a.publicKey.export({format:'der',type:'spki'}),y=b.publicKey.export({format:'der',type:'spki'});
 return {a,b,pub:{publicKey:x.toString('base64url'),pqPublicKey:y.toString('base64url'),pin:hash(x),pqPin:hash(y)}};
}
test('durable votes and certified cross-shard recovery survive restart without duplicate spend or credit',{skip:process.platform!=='linux',timeout:120000},t=>{
 const root=realpathSync(mkdtempSync(join(tmpdir(),'pay-shard-journal-'))),opened=new Set(),start=performance.now();
 const ids=['demo-east','demo-west'],keys=ids.map(()=>Array.from({length:16},()=>pair('ed25519'))),wallets=[pair('ec'),pair('ec')];
 const config={shards:ids.map((id,i)=>({id,authorities:keys[i].map(k=>k.pub)})),wallets:wallets.map((k,i)=>({id:i?'demo-bob':'demo-alice',shard:ids[i],initial:1000,publicKey:k.pub.publicKey,pqPublicKey:k.pub.pqPublicKey}))};
 const lab=openShardedPayLab(config);
 const opts=(i,j)=>{const k=keys[i][j];return {config,shard:ids[i],directory:join(root,i+'-'+j),credentials:k?{authorityPin:k.pub.pin,classicalPrivateKey:k.a.privateKey,pqPrivateKey:k.b.privateKey}:null};};
 const open=(i,j,createNew=false)=>{const d=openDurableShard({...opts(i,j),createNew});opened.add(d);return d;};
 const close=d=>{d.close();opened.delete(d);};
 function proof(amount,nonce=randomBytes(32).toString('hex')){
  const intent={network:lab.network,payer:'demo-alice',payee:'demo-bob',amount,nonce},b=lab.intentBytes(intent),k=wallets[0];
  return {intent,signature:sign('sha256',b,{key:k.a.privateKey,dsaEncoding:'ieee-p1363'}).toString('base64url'),pqSignature:sign(null,b,k.b.privateKey).toString('base64url')};
 }
 try{
  const voters=ids.map((_,i)=>Array.from({length:11},(_,j)=>open(i,j,true))),observers=ids.map((_,i)=>open(i,16,true));
  const tx=proof(300),ops=[{kind:'debit',proof:tx}],conflict=[{kind:'debit',proof:proof(200,tx.intent.nonce)}];
  function certify(i,operations,restart){
   const p=observers[i].proposal(operations),votes=voters[i].map(v=>v.prepare(operations));
   if(restart){for(let j=0;j<11;j++){close(voters[i][j]);voters[i][j]=open(i,j);}if(i===0)assert.throws(()=>voters[i][0].prepare(conflict));}
   const prepared={scope:p.scope,round:0,value:p.value,votes};
   assert.throws(()=>voters[i][0].commit({...prepared,votes:votes.slice(0,10)}));
   const certificate={prepared,commit:{scope:p.scope,round:0,value:p.value,votes:voters[i].map(v=>v.commit(prepared))}};
   const receipts=observers[i].finalize(operations,certificate);
   for(const v of voters[i]){v.finalize(operations,certificate);assert.deepEqual(v.snapshot(),observers[i].snapshot());}
   return {receipts,certificate};
  }
  const debit=certify(0,ops,true);
  close(observers[0]);observers[0]=open(0,16);
  const receipt=observers[0].recoverReceipts(1)[0];assert.deepEqual(receipt,debit.receipts[0]);
  assert.equal(observers[0].snapshot().balances['demo-alice'],700);
  assert.equal(observers[1].snapshot().balances['demo-bob'],1000);
  assert.throws(()=>observers[0].proposal(ops));assert.throws(()=>observers[0].proposal(conflict));
  const forged=structuredClone(receipt);forged.proof.intent.amount++;assert.throws(()=>observers[1].proposal([{kind:'claim',receipt:forged}]));
  certify(1,[{kind:'claim',receipt}],true);
  for(let i=0;i<2;i++){close(observers[i]);observers[i]=open(i,16);}
  assert.deepEqual(observers.map(s=>s.snapshot().balances),[{'demo-alice':700},{'demo-bob':1300}]);
  assert.throws(()=>observers[1].proposal([{kind:'claim',receipt}]));
  assert.throws(()=>observers[0].finalize(ops,debit.certificate));
  // Benchmark warm access against verified cold starts at multiple heights.
  const cold=[],warm=[];
  for(let h=2;h<=8;h++){
   // Fresh nonces, all transfers remain synthetic and one cent each.
   const transfer=certify(0,[{kind:'debit',proof:proof(1)}],false);
   certify(1,[{kind:'claim',receipt:transfer.receipts[0]}],false);
   const o=observers[0],before=o.metrics(),ts=performance.now();
   for(let j=0;j<12;j++)assert.equal(o.snapshot().height,h);
   warm.push(performance.now()-ts);
   const after=o.metrics();assert.equal(after.replayedBlocks,before.replayedBlocks);assert.equal(after.cacheHits-before.cacheHits,12);
   close(o);const tc=performance.now();observers[0]=open(0,16);assert.equal(observers[0].metrics().replayedBlocks,h);cold.push(performance.now()-tc);
  }
  assert.equal(observers[0].snapshot().balances['demo-alice']+observers[1].snapshot().balances['demo-bob'],2000);
  // The fixture obtains the anchor from a separate witness replica, not
  // by reading the untrusted checkpoint's own claimed height/root.
  const witness=voters[0][10].snapshot(),anchor={network:lab.network,shard:ids[0],height:witness.height,root:witness.root};
  const checkpoint=observers[0].checkpoint(),verified=lab.verifyCheckpoint(checkpoint,anchor);
  assert.deepEqual(verified.balances,witness.balances);assert.equal(verified.spent,witness.spent);assert.equal(verified.claimed,witness.claimed);
  assert.throws(()=>lab.verifyCheckpoint(checkpoint,{...anchor,height:anchor.height-1}));
  assert.throws(()=>lab.verifyCheckpoint(checkpoint,{...anchor,root:'f'.repeat(64)}));
  const edited=structuredClone(checkpoint);edited.balances['demo-alice']++;
  assert.throws(()=>lab.verifyCheckpoint(edited,anchor));
  const missingNonce=structuredClone(checkpoint);missingNonce.spent.pop();
  assert.throws(()=>lab.verifyCheckpoint(missingNonce,anchor));
  const insufficient=structuredClone(checkpoint);insufficient.certificate.commit.votes.pop();
  assert.throws(()=>lab.verifyCheckpoint(insufficient,anchor));
  assert.deepEqual(voters[0][0].checkpoint(),checkpoint);
  // A separate observer rehydrates just the certified state, not the
  // authority's next-height vote lock. It cannot sign even with valid keys.
  const restoredLab=openShardedPayLab(config),restored=restoredLab.openShard(ids[0],{checkpoint,anchor});
  assert.deepEqual(restored.snapshot(),observers[0].snapshot());
  assert.throws(()=>restored.openAuthority(opts(0,0).credentials));
  assert.throws(()=>restored.proposal(ops));
  assert.throws(()=>restored.proposal(conflict));
  const nextOps=[{kind:'debit',proof:proof(1)}],next=certify(0,nextOps,false);
  const receipts=restored.finalize(nextOps,next.certificate);
  assert.deepEqual(receipts,next.receipts);
  assert.deepEqual(restored.snapshot(),observers[0].snapshot());
  certify(1,[{kind:'claim',receipt:receipts[0]}],false);
  const latest=voters[0][10].snapshot();
  assert.throws(()=>openShardedPayLab(config).openShard(ids[0],{checkpoint,anchor:{...anchor,height:latest.height,root:latest.root}}));
  assert.equal(observers[0].snapshot().balances['demo-alice']+observers[1].snapshot().balances['demo-bob'],2000);
  t.diagnostic('SHARD_CHECKPOINT_V1 '+JSON.stringify({height:anchor.height,bytes:Buffer.byteLength(JSON.stringify(checkpoint)),verified:true}));
  // Detect external writes even when meta height/root are unchanged.
  const live=observers[0],other=new DatabaseSync(join(opts(0,16).directory,'shard.sqlite'));
  other.exec("UPDATE blocks SET digest='corrupt' WHERE height=2");other.close();
  assert.throws(()=>live.snapshot());assert.ok(live.metrics().externalInvalidations>=1);
  t.diagnostic('SHARD_CACHE_V1 '+JSON.stringify({heights:7,warmReadsPerHeight:12,coldMs:cold,warmMs:warm}));
  // Corruption detection, not an adversarial whole-database rollback test.
  close(observers[0]);const db=new DatabaseSync(join(opts(0,16).directory,'shard.sqlite'));db.exec("UPDATE blocks SET digest = 'corrupt' WHERE height=1");db.close();
  assert.throws(()=>open(0,16));
  t.diagnostic('SHARD_DURABLE_V1 '+JSON.stringify({shards:2,activeAuthorities:22,finalBlocks:2,initialTotal:2000,finalTotal:2000,elapsedMs:performance.now()-start,simulationOnly:true}));
 }finally{for(const d of opened)d.close();rmSync(root,{recursive:true,force:true});}
});
