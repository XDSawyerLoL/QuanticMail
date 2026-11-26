import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync,randomBytes,sign} from 'node:crypto';
import {mkdtempSync,rmSync,realpathSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {openShardedPayLab} from '../lib/quantic/pay-sharded-lab.mjs';
import {openDurableShard} from '../lib/quantic/pay-sharded-durable-lab.mjs';
const sha=b=>createHash('sha256').update(b).digest('hex');
function key(type='ed25519'){
 const cl=type==='ec'?generateKeyPairSync('ec',{namedCurve:'prime256v1'}):generateKeyPairSync(type),pq=generateKeyPairSync('ml-dsa-65');
 const a=cl.publicKey.export({type:'spki',format:'der'}),b=pq.publicKey.export({type:'spki',format:'der'});
 return {cl,pq,pub:{pin:sha(a),pqPin:sha(b),publicKey:a.toString('base64url'),pqPublicKey:b.toString('base64url')}};
}
const creds=k=>({authorityPin:k.pub.pin,classicalPrivateKey:k.cl.privateKey,pqPrivateKey:k.pq.privateKey});
test('certified hold, cross-shard capture and signed cancellation are exclusive across durable replicas',{skip:process.platform!=='linux',timeout:90000},t=>{
 const root=realpathSync(mkdtempSync(join(tmpdir(),'quantic-reserve-'))),replicas=[];
 try{
  const east='demo-east',west='demo-west',keys=Array.from({length:16},()=>key()),remote=Array.from({length:16},()=>key()),alice=key('ec'),bob=key('ec'),carol=key('ec');
  const config={shards:[{id:east,authorities:keys.map(k=>k.pub)},{id:west,authorities:remote.map(k=>k.pub)}],wallets:[{id:'demo-alice',shard:east,initial:1000,publicKey:alice.pub.publicKey,pqPublicKey:alice.pub.pqPublicKey},{id:'demo-shop',shard:west,initial:0,publicKey:bob.pub.publicKey,pqPublicKey:bob.pub.pqPublicKey},{id:'demo-person',shard:west,initial:0,publicKey:carol.pub.publicKey,pqPublicKey:carol.pub.pqPublicKey}]};
  const lab=openShardedPayLab(config,{reservationsEnabled:true}),source=lab.openShard(east),target=lab.openShard(west);
  function proof(payee,amount,nonce=randomBytes(32).toString('hex')){
   const intent={network:lab.network,payer:'demo-alice',payee,amount,nonce},bytes=lab.intentBytes(intent);
   return {intent,signature:sign('sha256',bytes,{key:alice.cl.privateKey,dsaEncoding:'ieee-p1363'}).toString('base64url'),pqSignature:sign(null,bytes,alice.pq.privateKey).toString('base64url')};
  }
  function nativeApproval(p){
   const i=p.intent,issued=Date.now(),expires=issued+120000,spki=alice.cl.publicKey.export({type:'spki',format:'der'}),pq=alice.pq.publicKey.export({type:'spki',format:'der'});
   const jwk=alice.cl.publicKey.export({format:'jwk'}),point=Buffer.concat([Buffer.from([4]),Buffer.from(jwk.x,'base64url'),Buffer.from(jwk.y,'base64url')]),s=sha(spki),d=sha(pq),intent={Payee:i.payee,Cents:i.amount,Nonce:i.nonce,Issued:issued,Expires:expires};
   const b=Buffer.from(JSON.stringify(['quantic-pay-native-simulation/v1',s,d,i.payee,i.amount,'EUR',i.nonce,issued,expires,false]));
   return {intent,signingPin:s,pqPin:d,classicalSignature:sign('sha256',b,{key:alice.cl.privateKey,dsaEncoding:'ieee-p1363'}).toString('base64url'),pqSignature:sign(null,b,alice.pq.privateKey).toString('base64url'),classicalPublic:point.toString('base64url'),pqPublic:pq.toString('base64url'),realPaymentAuthorized:false};
  }
  const pA=proof('demo-shop',700),pB=proof('demo-person',400),pC=proof('demo-person',300);
  const reserveA=[{kind:'reserve',proof:pA}],reserveB=[{kind:'reserve',proof:pB}],reserveC=[{kind:'reserve',proof:pC}];
  assert.throws(()=>source.proposal([...reserveA,...reserveB]));
  assert.notEqual(source.proposal(reserveA).value,source.proposal(reserveB).value);
  for(let i=0;i<11;i++)replicas.push(openDurableShard({config,shard:east,directory:join(root,String(i)),credentials:creds(keys[i]),reservationsEnabled:true,createNew:true}));
  const candidate=source.proposal(reserveA),prepared={scope:candidate.scope,round:0,value:candidate.value,votes:replicas.map(r=>r.prepare(reserveA))};
  assert.throws(()=>replicas[0].prepare(reserveB));
  replicas[0].close();replicas[0]=openDurableShard({config,shard:east,directory:join(root,'0'),credentials:creds(keys[0]),reservationsEnabled:true});
  assert.throws(()=>replicas[0].prepare(reserveB));
  const certificate={prepared,commit:{scope:candidate.scope,round:0,value:candidate.value,votes:replicas.map(r=>r.commit(prepared))}};
  assert.deepEqual(source.finalize(reserveA,certificate),[]);
  for(const r of replicas)r.finalize(reserveA,certificate);
  assert.equal(source.snapshot().balances['demo-alice'],300);assert.equal(source.snapshot().reservedCents,700);
  assert.throws(()=>source.proposal(reserveB));
  const cp=source.checkpoint(),snap=source.snapshot(),anchor={network:lab.network,shard:east,height:snap.height,root:snap.root};
  const verified=lab.verifyCheckpoint(cp,anchor);
  assert.equal(verified.balances['demo-alice'],300);
  assert.throws(()=>lab.verifyCheckpoint({...cp,holds:[]},anchor));
  assert.throws(()=>lab.verifyCheckpoint({...cp,balances:{...cp.balances,'demo-alice':1000}},anchor));
  const tampered=structuredClone(cp);tampered.holds[0][1].intent.amount=900;assert.throws(()=>lab.verifyCheckpoint(tampered,anchor));
  const approval=nativeApproval(pA),capture=[{kind:'capture',proof:pA,approval}];
  assert.throws(()=>source.proposal([{kind:'capture',proof:pA,approval:{...approval,intent:{...approval.intent,Cents:701}}}]));
  assert.throws(()=>source.proposal([{kind:'capture',proof:pB,approval:nativeApproval(pB)}]));
  function certify(shard,ops,ks){const p=shard.proposal(ops),nodes=ks.slice(0,11).map(k=>shard.openAuthority(creds(k)));const prep={scope:p.scope,round:0,value:p.value,votes:nodes.map(n=>n.prepare(ops))};return {prepared:prep,commit:{scope:p.scope,round:0,value:p.value,votes:nodes.map(n=>n.commit(prep))}};}
  const receipt=source.finalize(capture,certify(source,capture,keys))[0];
  assert.equal(receipt.kind,'capture');assert.equal(lab.verifyDebit(receipt).id,sha(Buffer.from(JSON.stringify(['quantic-shard-id/v1',lab.intentBytes(pA.intent).toString('hex')]))));
  assert.throws(()=>source.proposal(capture));assert.throws(()=>source.proposal(reserveA));
  assert.equal(source.snapshot().reservedCents,0);
  const claim=[{kind:'claim',receipt}],destCert=certify(target,claim,remote);target.finalize(claim,destCert);assert.throws(()=>target.proposal(claim));
  assert.equal(target.snapshot().balances['demo-shop'],700);
  const holdC=source.finalize(reserveC,certify(source,reserveC,keys));assert.equal(holdC.length,0);
  assert.equal(source.snapshot().balances['demo-alice'],0);assert.equal(source.snapshot().reservedCents,300);
  const msg=lab.cancelBytes(pC),cancel={kind:'cancel',proof:pC,signature:sign('sha256',msg,{key:alice.cl.privateKey,dsaEncoding:'ieee-p1363'}).toString('base64url'),pqSignature:sign(null,msg,alice.pq.privateKey).toString('base64url')};
  assert.throws(()=>source.proposal([{...cancel,signature:sign('sha256',msg,{key:bob.cl.privateKey,dsaEncoding:'ieee-p1363'}).toString('base64url')}]));
  source.finalize([cancel],certify(source,[cancel],keys));
  assert.equal(source.snapshot().balances['demo-alice'],300);assert.equal(source.snapshot().reservedCents,0);
  assert.throws(()=>source.proposal([cancel]));assert.throws(()=>source.proposal(reserveC));
  assert.equal(source.snapshot().balances['demo-alice']+target.snapshot().balances['demo-shop']+target.snapshot().balances['demo-person'],1000);
  t.diagnostic('SHARDED_RESERVATION_V1 '+JSON.stringify({durableValidators:11,reserved:700,captured:700,cancelled:300,overspendRefused:true,crossShardClaimedOnce:true,conserved:1000,simulationOnly:true}));
 }finally{for(const r of replicas)r.close();rmSync(root,{recursive:true,force:true});}
});
