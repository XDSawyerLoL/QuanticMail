import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync,randomBytes,sign} from 'node:crypto';
import {mkdtempSync,realpathSync,rmSync} from 'node:fs';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {openShardedPayLab} from '../lib/quantic/pay-sharded-lab.mjs';
import {openDurableShard} from '../lib/quantic/pay-sharded-durable-lab.mjs';
const hash=x=>createHash('sha256').update(JSON.stringify(x)).digest('hex');
const sha=b=>createHash('sha256').update(b).digest('hex');
function key(type='ed25519'){
 const cl=type==='ec'?generateKeyPairSync('ec',{namedCurve:'prime256v1'}):generateKeyPairSync(type),pq=generateKeyPairSync('ml-dsa-65');
 const a=cl.publicKey.export({format:'der',type:'spki'}),b=pq.publicKey.export({format:'der',type:'spki'});
 return {cl,pq,pub:{pin:sha(a),pqPin:sha(b),publicKey:a.toString('base64url'),pqPublicKey:b.toString('base64url')}};
}
const creds=k=>({authorityPin:k.pub.pin,classicalPrivateKey:k.cl.privateKey,pqPrivateKey:k.pq.privateKey});
test('destination prepares an independently certified inbox before COMMIT; both shard replicas recover after restart',{skip:process.platform!=='linux',timeout:120000},t=>{
 const root=realpathSync(mkdtempSync(join(tmpdir(),'quantic-inbound-'))),voters=[],dbs=[];
 try{
  const east='demo-east',west='demo-west',old=Array.from({length:16},()=>key()),incoming=Array.from({length:16},()=>key()),alice=key('ec'),bob=key('ec');
  const config={shards:[{id:east,authorities:old.map(k=>k.pub)},{id:west,authorities:incoming.map(k=>k.pub)}],wallets:[{id:'demo-alice',shard:east,initial:1000,publicKey:alice.pub.publicKey,pqPublicKey:alice.pub.pqPublicKey},{id:'demo-shop',shard:west,initial:0,publicKey:bob.pub.publicKey,pqPublicKey:bob.pub.pqPublicKey}]};
  const mode={reservationsEnabled:true,crossShardAtomicEnabled:true,inboundPreparationEnabled:true},lab=openShardedPayLab(config,mode);
  const source=lab.openShard(east),target=lab.openShard(west);
  function makeProof(amount){
   const intent={network:lab.network,payer:'demo-alice',payee:'demo-shop',amount,nonce:randomBytes(32).toString('hex')},bytes=lab.intentBytes(intent);
   return {intent,signature:sign('sha256',bytes,{key:alice.cl.privateKey,dsaEncoding:'ieee-p1363'}).toString('base64url'),pqSignature:sign(null,bytes,alice.pq.privateKey).toString('base64url')};
  }
  function approval(p){
   const i=p.intent,issued=Date.now(),expires=issued+120000,spki=alice.cl.publicKey.export({type:'spki',format:'der'}),pq=alice.pq.publicKey.export({type:'spki',format:'der'}),jwk=alice.cl.publicKey.export({format:'jwk'}),point=Buffer.concat([Buffer.from([4]),Buffer.from(jwk.x,'base64url'),Buffer.from(jwk.y,'base64url')]),s=sha(spki),d=sha(pq),intent={Payee:i.payee,Cents:i.amount,Nonce:i.nonce,Issued:issued,Expires:expires},msg=Buffer.from(JSON.stringify(['quantic-pay-native-simulation/v1',s,d,i.payee,i.amount,'EUR',i.nonce,issued,expires,false]));
   return {intent,signingPin:s,pqPin:d,classicalSignature:sign('sha256',msg,{key:alice.cl.privateKey,dsaEncoding:'ieee-p1363'}).toString('base64url'),pqSignature:sign(null,msg,alice.pq.privateKey).toString('base64url'),classicalPublic:point.toString('base64url'),pqPublic:pq.toString('base64url'),realPaymentAuthorized:false};
  }
  function certify(shard,ops,keys){
   const p=shard.proposal(ops),nodes=keys.slice(0,11).map(k=>shard.openAuthority(creds(k))),prepared={scope:p.scope,round:0,value:p.value,votes:nodes.map(n=>n.prepare(ops))};
   return {prepared,commit:{scope:p.scope,round:0,value:p.value,votes:nodes.map(n=>n.commit(prepared))}};
  }
  function anchor(shard,id){const snap=shard.snapshot();return {network:lab.network,shard:id,height:snap.height,root:snap.root};}
  function openDB(id,createNew=false){const d=openDurableShard({config,shard:id,directory:join(root,'db-'+id),createNew,...mode});dbs.push(d);return d;}
  let aDB=openDB(east,true),bDB=openDB(west,true);
  function append(shard,db,ops,keys){const cert=certify(shard,ops,keys),receipts=shard.finalize(ops,cert),persisted=db.finalize(ops,cert);assert.deepEqual(persisted,receipts);return receipts;}
  const p=makeProof(600),reserve=[{kind:'reserve',proof:p}];
  append(source,aDB,reserve,old);
  const savedSource={checkpoint:source.checkpoint(),anchor:anchor(source,east)};
  const inbound=[{kind:'prepare-inbound',proof:p,sourceCheckpoint:savedSource.checkpoint,sourceAnchor:savedSource.anchor}];
  assert.throws(()=>source.proposal([{kind:'capture',proof:p,approval:approval(p)}]));
  assert.throws(()=>target.proposal([{kind:'prepare-inbound',proof:p,sourceCheckpoint:savedSource.checkpoint,sourceAnchor:{...savedSource.anchor,root:'f'.repeat(64)}}]));
  append(target,bDB,inbound,incoming);
  assert.equal(target.snapshot().pendingInbound,1);assert.equal(target.snapshot().balances['demo-shop'],0);
  const ready={checkpoint:target.checkpoint(),anchor:anchor(target,west)};
  const observing=openShardedPayLab(config,mode).openShard(west,ready);
  assert.equal(observing.snapshot().pendingInbound,1);
  assert.throws(()=>target.proposal(inbound));
  assert.throws(()=>lab.preparedDecision(p,{checkpoint:{...ready.checkpoint,incoming:[]},anchor:ready.anchor}));
  assert.throws(()=>lab.preparedDecision(p,{checkpoint:ready.checkpoint,anchor:{...ready.anchor,root:'f'.repeat(64)}}));
  const decisionLab=lab.preparedDecision(p,ready);
  assert.throws(()=>lab.abortDecision(p).value('commit'));
  const transferId=hash(['quantic-shard-id/v1',lab.intentBytes(p.intent).toString('hex')]);
  const decisionNodes=old.slice(0,11).map((k,i)=>decisionLab.openAuthority({directory:join(root,'vote-'+i),createNew:true,credentials:creds(k)}));voters.push(...decisionNodes);
  const prepared={scope:decisionLab.scope,round:0,value:decisionLab.value('commit'),votes:decisionNodes.map(n=>n.prepare('commit'))};
  decisionNodes[0].close();voters.splice(voters.indexOf(decisionNodes[0]),1);
  decisionNodes[0]=decisionLab.openAuthority({directory:join(root,'vote-0'),credentials:creds(old[0])});voters.push(decisionNodes[0]);
  assert.throws(()=>decisionNodes[0].prepare('abort'));
  const certificate={prepared,commit:{scope:decisionLab.scope,round:0,value:decisionLab.value('commit'),votes:decisionNodes.map(n=>n.commit('commit',prepared))}};
  const decision={outcome:'commit',certificate,ready};
  assert.equal(decisionLab.verifyDecision({outcome:'commit',certificate},'commit').transferId,transferId);
  assert.throws(()=>source.proposal([{kind:'capture',proof:p,approval:approval(p),decision:{outcome:'commit',certificate}}]));
  const altered=structuredClone(decision);altered.ready.checkpoint.incoming[0][1].proof.intent.amount++;
  assert.throws(()=>source.proposal([{kind:'capture',proof:p,approval:approval(p),decision:altered}]));
  const capture=[{kind:'capture',proof:p,approval:approval(p),decision}],receipts=append(source,aDB,capture,old);
  assert.equal(receipts.length,1);assert.equal(target.snapshot().balances['demo-shop'],0);
  assert.throws(()=>source.proposal([{kind:'cancel',proof:p,decision:{outcome:'abort',certificate}}]));
  // Crash both shards after the source commit was certified but before
  // destination credit; do not reconstruct votes or ask for a new COMMIT.
  aDB.close();bDB.close();dbs.splice(0,dbs.length);
  aDB=openDB(east);bDB=openDB(west);
  assert.equal(aDB.snapshot().height,2);assert.equal(aDB.snapshot().reserved,0);
  assert.equal(bDB.snapshot().height,1);assert.equal(bDB.snapshot().pendingInbound,1);
  const recovered=aDB.recoverReceipts(2);assert.deepEqual(recovered,receipts);
  assert.equal(lab.verifyDebit(recovered[0]).id,transferId);
  const claim=[{kind:'claim',receipt:recovered[0]}];
  assert.throws(()=>target.proposal([{kind:'release-inbound',proof:p,decision:{outcome:'abort',certificate}}]));
  append(target,bDB,claim,incoming);
  assert.equal(target.snapshot().balances['demo-shop'],600);assert.equal(target.snapshot().pendingInbound,0);
  assert.throws(()=>target.proposal(claim));
  assert.throws(()=>target.proposal([{kind:'release-inbound',proof:p,decision:{outcome:'abort',certificate}}]));
  assert.equal(source.snapshot().balances['demo-alice']+target.snapshot().balances['demo-shop'],1000);
  // A different transfer deliberately terminates with an ABORT. Its
  // destination inbox is released, and the sender gets precisely one refund.
  const q=makeProof(400),rsv=[{kind:'reserve',proof:q}];
  append(source,aDB,rsv,old);
  const otherSource={checkpoint:source.checkpoint(),anchor:anchor(source,east)};
  const inboundQ=[{kind:'prepare-inbound',proof:q,sourceCheckpoint:otherSource.checkpoint,sourceAnchor:otherSource.anchor}];
  append(target,bDB,inboundQ,incoming);
  const abortLab=lab.abortDecision(q);
  const abortNodes=old.slice(0,11).map((k,i)=>abortLab.openAuthority({directory:join(root,'abort-'+i),createNew:true,credentials:creds(k)}));voters.push(...abortNodes);
  const av={scope:abortLab.scope,round:0,value:abortLab.value('abort'),votes:abortNodes.map(n=>n.prepare('abort'))};
  const ac={prepared:av,commit:{scope:abortLab.scope,round:0,value:abortLab.value('abort'),votes:abortNodes.map(n=>n.commit('abort',av))}};
  const abort={outcome:'abort',certificate:ac};
  assert.throws(()=>source.proposal([{kind:'capture',proof:q,approval:approval(q),decision:abort}]));
  append(source,aDB,[{kind:'cancel',proof:q,decision:abort}],old);
  append(target,bDB,[{kind:'release-inbound',proof:q,decision:abort}],incoming);
  assert.equal(target.snapshot().pendingInbound,0);assert.equal(source.snapshot().reservedCents,0);
  assert.equal(source.snapshot().balances['demo-alice'],400);assert.equal(target.snapshot().balances['demo-shop'],600);
  assert.throws(()=>source.proposal([{kind:'cancel',proof:q,decision:abort}]));
  assert.throws(()=>target.proposal([{kind:'release-inbound',proof:q,decision:abort}]));
  t.diagnostic('PREPARED_CROSS_SHARD_RECOVERY_V1 '+JSON.stringify({sourceCommitted:600,sourceAborted:400,recoveredAfterRestart:true,destinationCreditedOnce:true,conserved:1000,simulationOnly:true}));
 }finally{for(const v of voters)v.close();for(const db of dbs)db.close();rmSync(root,{recursive:true,force:true});}
});
