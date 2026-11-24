import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync,randomBytes,sign} from 'node:crypto';
import {mkdtempSync,realpathSync,rmSync} from 'node:fs';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {openShardedPayLab} from '../lib/quantic/pay-sharded-lab.mjs';
import {openCrossShardDecisionLab} from '../lib/quantic/pay-cross-shard-decision-lab.mjs';
const hash=x=>createHash('sha256').update(JSON.stringify(x)).digest('hex');
const sha=b=>createHash('sha256').update(b).digest('hex');
function key(type='ed25519'){
 const cl=type==='ec'?generateKeyPairSync('ec',{namedCurve:'prime256v1'}):generateKeyPairSync(type),pq=generateKeyPairSync('ml-dsa-65');
 const a=cl.publicKey.export({type:'spki',format:'der'}),b=pq.publicKey.export({type:'spki',format:'der'});
 return {cl,pq,pub:{pin:sha(a),pqPin:sha(b),publicKey:a.toString('base64url'),pqPublicKey:b.toString('base64url')}};
}
const creds=k=>({authorityPin:k.pub.pin,classicalPrivateKey:k.cl.privateKey,pqPrivateKey:k.pq.privateKey});
test('one durable hybrid finality decision fences cross-shard credit against conflicting refund',{skip:process.platform!=='linux',timeout:100000},t=>{
 const root=realpathSync(mkdtempSync(join(tmpdir(),'quantic-atomic-settlement-'))),stores=[];
 try{
  const east='demo-east',west='demo-west',authorities=Array.from({length:16},()=>key()),receiverAuthorities=Array.from({length:16},()=>key()),payer=key('ec'),receiver=key('ec');
  const config={shards:[{id:east,authorities:authorities.map(k=>k.pub)},{id:west,authorities:receiverAuthorities.map(k=>k.pub)}],wallets:[{id:'demo-alice',shard:east,initial:1000,publicKey:payer.pub.publicKey,pqPublicKey:payer.pub.pqPublicKey},{id:'demo-shop',shard:west,initial:0,publicKey:receiver.pub.publicKey,pqPublicKey:receiver.pub.pqPublicKey}]};
  const lab=openShardedPayLab(config,{reservationsEnabled:true,crossShardAtomicEnabled:true}),source=lab.openShard(east),target=lab.openShard(west);
  function proof(amount){
   const intent={network:lab.network,payer:'demo-alice',payee:'demo-shop',amount,nonce:randomBytes(32).toString('hex')},bytes=lab.intentBytes(intent);
   return {intent,signature:sign('sha256',bytes,{key:payer.cl.privateKey,dsaEncoding:'ieee-p1363'}).toString('base64url'),pqSignature:sign(null,bytes,payer.pq.privateKey).toString('base64url')};
  }
  function approval(p){
   const i=p.intent,issued=Date.now(),expires=issued+120000,spki=payer.cl.publicKey.export({type:'spki',format:'der'}),pq=payer.pq.publicKey.export({type:'spki',format:'der'}),jwk=payer.cl.publicKey.export({format:'jwk'}),point=Buffer.concat([Buffer.from([4]),Buffer.from(jwk.x,'base64url'),Buffer.from(jwk.y,'base64url')]),s=sha(spki),d=sha(pq),intent={Payee:i.payee,Cents:i.amount,Nonce:i.nonce,Issued:issued,Expires:expires};
   const data=Buffer.from(JSON.stringify(['quantic-pay-native-simulation/v1',s,d,i.payee,i.amount,'EUR',i.nonce,issued,expires,false]));
   return {intent,signingPin:s,pqPin:d,classicalSignature:sign('sha256',data,{key:payer.cl.privateKey,dsaEncoding:'ieee-p1363'}).toString('base64url'),pqSignature:sign(null,data,payer.pq.privateKey).toString('base64url'),classicalPublic:point.toString('base64url'),pqPublic:pq.toString('base64url'),realPaymentAuthorized:false};
  }
  function certify(shard,ops,keys){
   const p=shard.proposal(ops),v=keys.slice(0,11).map(k=>shard.openAuthority(creds(k))),prepared={scope:p.scope,round:0,value:p.value,votes:v.map(k=>k.prepare(ops))};
   return {prepared,commit:{scope:p.scope,round:0,value:p.value,votes:v.map(k=>k.commit(prepared))}};
  }
  function transferId(p){return hash(['quantic-shard-id/v1',lab.intentBytes(p.intent).toString('hex')]);}
  function decide(p,outcome,tag){
   const decisionLab=openCrossShardDecisionLab({network:lab.network,source:east,destination:west,transferId:transferId(p),authorities:authorities.map(k=>k.pub)});
   const nodes=authorities.slice(0,11).map((k,j)=>decisionLab.openAuthority({directory:join(root,tag+'-'+j),createNew:true,credentials:creds(k)}));stores.push(...nodes);
   const prepared={scope:decisionLab.scope,round:0,value:decisionLab.value(outcome),votes:nodes.map(n=>n.prepare(outcome))};
   nodes[0].close();stores.splice(stores.indexOf(nodes[0]),1);
   nodes[0]=decisionLab.openAuthority({directory:join(root,tag+'-0'),credentials:creds(authorities[0])});stores.push(nodes[0]);
   assert.deepEqual(nodes[0].prepare(outcome),prepared.votes[0]);
   const other=outcome==='commit'?'abort':'commit';
   assert.throws(()=>nodes[0].prepare(other));assert.throws(()=>nodes[1].prepare(other));
   const certificate={prepared,commit:{scope:decisionLab.scope,round:0,value:decisionLab.value(outcome),votes:nodes.map(n=>n.commit(outcome,prepared))}};
   const decision={outcome,certificate};assert.equal(decisionLab.verifyDecision(decision,outcome).transferId,transferId(p));
   assert.throws(()=>decisionLab.verifyDecision(decision,other));
   assert.throws(()=>decisionLab.verifyDecision({...decision,certificate:{...certificate,commit:{...certificate.commit,votes:certificate.commit.votes.slice(0,10)}}},outcome));
   return decision;
  }
  const a=proof(600),b=proof(400),reserveA=[{kind:'reserve',proof:a}];
  assert.throws(()=>source.proposal([{kind:'debit',proof:a}]));
  source.finalize(reserveA,certify(source,reserveA,authorities));
  assert.equal(source.snapshot().balances['demo-alice'],400);
  assert.throws(()=>source.proposal([{kind:'reserve',proof:proof(401)}]));
  assert.throws(()=>source.proposal([{kind:'capture',proof:a,approval:approval(a)}]));
  assert.throws(()=>source.proposal([{kind:'cancel',proof:a}]));
  const commit=decide(a,'commit','c');
  assert.throws(()=>source.proposal([{kind:'cancel',proof:a,decision:commit}]));
  const capture=[{kind:'capture',proof:a,approval:approval(a),decision:commit}],rcpt=source.finalize(capture,certify(source,capture,authorities))[0];
  assert.equal(rcpt.kind,'capture');assert.equal(rcpt.decision.outcome,'commit');
  const lostCredit=target.snapshot();assert.equal(lostCredit.balances['demo-shop'],0);
  assert.throws(()=>source.proposal([{kind:'cancel',proof:a,decision:commit}]));
  assert.throws(()=>source.proposal(capture));
  const tampered=structuredClone(rcpt);tampered.decision.outcome='abort';assert.throws(()=>lab.verifyDebit(tampered));
  const truncated=structuredClone(rcpt);truncated.decision.certificate.commit.votes.pop();assert.throws(()=>lab.verifyDebit(truncated));
  const claim=[{kind:'claim',receipt:rcpt}];target.finalize(claim,certify(target,claim,receiverAuthorities));
  assert.equal(target.snapshot().balances['demo-shop'],600);assert.throws(()=>target.proposal(claim));
  const cp=source.checkpoint(),snapshot=source.snapshot(),anchor={network:lab.network,shard:east,height:snapshot.height,root:snapshot.root};
  lab.verifyCheckpoint(cp,anchor);
  const observer=openShardedPayLab(config,{reservationsEnabled:true,crossShardAtomicEnabled:true}).openShard(east,{checkpoint:cp,anchor});
  assert.equal(observer.snapshot().balances['demo-alice'],400);assert.equal(observer.snapshot().reservedCents,0);
  const reserveB=[{kind:'reserve',proof:b}];source.finalize(reserveB,certify(source,reserveB,authorities));
  assert.equal(source.snapshot().balances['demo-alice'],0);assert.equal(source.snapshot().reservedCents,400);
  const abort=decide(b,'abort','a');
  assert.throws(()=>source.proposal([{kind:'capture',proof:b,approval:approval(b),decision:abort}]));
  const cancel=[{kind:'cancel',proof:b,decision:abort}];source.finalize(cancel,certify(source,cancel,authorities));
  assert.throws(()=>source.proposal(cancel));
  assert.throws(()=>source.proposal([{kind:'capture',proof:b,approval:approval(b),decision:abort}]));
  assert.equal(source.snapshot().balances['demo-alice'],400);assert.equal(source.snapshot().reservedCents,0);
  assert.equal(source.snapshot().balances['demo-alice']+target.snapshot().balances['demo-shop'],1000);
  t.diagnostic('CROSS_SHARD_DECISION_V1 '+JSON.stringify({sourceFinalizedHeights:source.snapshot().height,destinationFinalizedHeights:target.snapshot().height,commit:600,abort:400,conserved:1000,decisionWitnesses:11,replayConflictRefused:true,simulationOnly:true}));
 }finally{for(const n of stores)n.close();rmSync(root,{recursive:true,force:true});}
});
