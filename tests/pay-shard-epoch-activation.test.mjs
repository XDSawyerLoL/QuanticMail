import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,createHash,randomBytes,sign} from 'node:crypto';
import {openShardedPayLab} from '../lib/quantic/pay-sharded-lab.mjs';
const sha=b=>createHash('sha256').update(b).digest('hex');
function key(type){
 const cl=type==='ec'?generateKeyPairSync('ec',{namedCurve:'prime256v1'}):generateKeyPairSync(type),pq=generateKeyPairSync('ml-dsa-65');
 const a=cl.publicKey.export({type:'spki',format:'der'}),b=pq.publicKey.export({type:'spki',format:'der'});
 return {cl,pq,pub:{pin:sha(a),pqPin:sha(b),publicKey:a.toString('base64url'),pqPublicKey:b.toString('base64url')}};
}
const creds=k=>({authorityPin:k.pub.pin,classicalPrivateKey:k.cl.privateKey,pqPrivateKey:k.pq.privateKey});
const roster=ks=>ks.map(k=>k.pub);
function votes(ks,b){return ks.slice(0,11).map(k=>({pin:k.pub.pin,pqPin:k.pub.pqPin,signature:sign(null,b,k.cl.privateKey).toString('base64url'),pqSignature:sign(null,b,k.pq.privateKey).toString('base64url')})).sort((a,b)=>a.pin<b.pin?-1:1);}
test('committee epoch activation fences old votes, preserves historical debit receipts and binds external trust',{timeout:60000},t=>{
 const east='demo-east',west='demo-west',old=Array.from({length:16},()=>key('ed25519')),next=Array.from({length:16},()=>key('ed25519')),other=Array.from({length:16},()=>key('ed25519')),a=key('ec'),b=key('ec');
 const config={shards:[{id:east,authorities:roster(old)},{id:west,authorities:roster(other)}],wallets:[{id:'demo-alice',shard:east,initial:1000,publicKey:a.pub.publicKey,pqPublicKey:a.pub.pqPublicKey},{id:'demo-bob',shard:west,initial:0,publicKey:b.pub.publicKey,pqPublicKey:b.pub.pqPublicKey}]};
 const lab=openShardedPayLab(config,{rotationEnabled:true}),source=lab.openShard(east),stale=openShardedPayLab(config).openShard(east),remote=openShardedPayLab(config,{rotationEnabled:true}),target=remote.openShard(west);
 function debit(amount){const intent={network:lab.network,payer:'demo-alice',payee:'demo-bob',amount,nonce:randomBytes(32).toString('hex')},data=lab.intentBytes(intent);return [{kind:'debit',proof:{intent,signature:sign('sha256',data,{key:a.cl.privateKey,dsaEncoding:'ieee-p1363'}).toString('base64url'),pqSignature:sign(null,data,a.pq.privateKey).toString('base64url')}}];}
 function cert(s,ops,ks){
  const p=s.proposal(ops),ns=ks.slice(0,11).map(k=>s.openAuthority(creds(k)));
  const prepared={scope:p.scope,round:0,value:p.value,votes:ns.map(n=>n.prepare(ops))};
  return {prepared,commit:{scope:p.scope,round:0,value:p.value,votes:ns.map(n=>n.commit(prepared))}};
 }
 const first=debit(100),c1=cert(source,first,old),r1=source.finalize(first,c1)[0];stale.finalize(first,c1);
 const {checkpoint,anchor}=source.freezeForHandoff();
 assert.throws(()=>source.proposal(debit(1)));assert.throws(()=>source.openAuthority(creds(old[0])));
 const p=source.draftHandoff(roster(next)),outgoing=votes(old,source.handoffOutgoingBytes(p)),incoming=votes(next,source.handoffIncomingBytes(p,outgoing)),record={proposal:p,outgoing,incoming};
 assert.throws(()=>source.activateHandoff({...record,incoming:incoming.slice(0,10)}));
 assert.throws(()=>source.proposal(debit(1)));
 assert.throws(()=>remote.importHandoff(record,checkpoint,{...anchor,root:'f'.repeat(64)}));
 const activated=source.activateHandoff(record);
 assert.equal(activated.activationHeight,2);assert.equal(activated.epoch,1);
 assert.deepEqual(remote.importHandoff(record,checkpoint,anchor),activated);
 assert.throws(()=>remote.importHandoff(record,checkpoint,anchor));
 assert.throws(()=>source.openAuthority(creds(old[0])));
 assert.equal(lab.verifyDebit(r1).destination,west);assert.equal(remote.verifyDebit(r1).destination,west);
 const second=debit(200),wrongCert=cert(stale,second,old),wrongReceipt=stale.finalize(second,wrongCert)[0];
 assert.throws(()=>source.finalize(second,wrongCert));assert.throws(()=>lab.verifyDebit(wrongReceipt));assert.throws(()=>remote.verifyDebit(wrongReceipt));
 const c2=cert(source,second,next),r2=source.finalize(second,c2)[0];
 assert.equal(remote.verifyDebit(r2).destination,west);assert.equal(remote.verifyDebit(r1).destination,west);
 const claims=[r1,r2].map(receipt=>({kind:'claim',receipt}));target.finalize(claims,cert(target,claims,other));
 assert.equal(source.snapshot().balances['demo-alice'],700);assert.equal(target.snapshot().balances['demo-bob'],300);
 assert.throws(()=>target.proposal(claims));
 const history=lab.committeeHistory(east);assert.deepEqual(history,remote.committeeHistory(east));assert.deepEqual(history.map(e=>e.start),[1,2]);
 t.diagnostic('SHARD_EPOCH_ACTIVATION_V1 '+JSON.stringify({oldAuthorities:16,newAuthorities:16,sourceHeight:2,historicalClaims:2,conserved:1000,simulationOnly:true}));
});
