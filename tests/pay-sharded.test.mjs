import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync,randomBytes,sign} from 'node:crypto';
import {openShardedPayLab} from '../lib/quantic/pay-sharded-lab.mjs';
const sha=b=>createHash('sha256').update(b).digest('hex');
function pair(type){
 const a=type==='ec'?generateKeyPairSync('ec',{namedCurve:'prime256v1'}):generateKeyPairSync(type),b=generateKeyPairSync('ml-dsa-65');
 const x=a.publicKey.export({format:'der',type:'spki'}),y=b.publicKey.export({format:'der',type:'spki'});
 return {a,b,publicKey:x.toString('base64url'),pqPublicKey:y.toString('base64url'),pin:sha(x),pqPin:sha(y)};
}
test('three independent committees, certified cross-shard debit and claim, no mint or double spend',t=>{
 const keys=Array.from({length:3},()=>Array.from({length:16},()=>pair('ed25519'))),shardIds=['demo-east','demo-west','demo-north'];
 const accounts=['demo-alice','demo-bob','demo-carol','demo-dan'],walletKeys=accounts.map(()=>pair('ec'));
 const config={shards:shardIds.map((id,i)=>({id,authorities:keys[i].map(({pin,pqPin,publicKey,pqPublicKey})=>({pin,pqPin,publicKey,pqPublicKey}))})),wallets:accounts.map((id,i)=>({id,shard:shardIds[i===3?0:i],initial:1000,publicKey:walletKeys[i].publicKey,pqPublicKey:walletKeys[i].pqPublicKey}))};
 const lab=openShardedPayLab(config),replicas=shardIds.map((id)=>Array.from({length:11},()=>openShardedPayLab(config).openShard(id))),coordinators=shardIds.map(lab.openShard);
 assert.throws(()=>lab.openShard(shardIds[0]));
 const sum=()=>coordinators.reduce((n,s)=>n+Object.values(s.snapshot().balances).reduce((a,b)=>a+b,0),0);
 function tx(i,j,amount,nonce=randomBytes(32).toString('hex')){
  const intent={network:lab.network,payer:accounts[i],payee:accounts[j],amount,nonce},data=lab.intentBytes(intent),k=walletKeys[i];
  return {intent,signature:sign('sha256',data,{key:k.a.privateKey,dsaEncoding:'ieee-p1363'}).toString('base64url'),pqSignature:sign(null,data,k.b.privateKey).toString('base64url')};
 }
 function certify(i,ops){
  const s=coordinators[i],p=s.proposal(ops),voters=replicas[i].map((r,j)=>{const k=keys[i][j];return r.openAuthority({authorityPin:k.pin,classicalPrivateKey:k.a.privateKey,pqPrivateKey:k.b.privateKey});});
  const prepared={scope:p.scope,round:0,value:p.value,votes:voters.map(v=>v.prepare(ops))};
  assert.throws(()=>voters[0].commit({...prepared,votes:prepared.votes.slice(0,10)}));
  const final={prepared,commit:{scope:p.scope,round:0,value:p.value,votes:voters.map(v=>v.commit(prepared))}};
  const results=s.finalize(ops,final);for(const r of replicas[i]){r.finalize(ops,final);assert.deepEqual(r.snapshot(),s.snapshot());}return {results,final};
 }
 const nonce=randomBytes(32).toString('hex'),a=tx(0,1,300,nonce),b=tx(0,2,200,nonce);
 assert.throws(()=>coordinators[0].proposal([{kind:'debit',proof:a},{kind:'debit',proof:b}]));
 assert.throws(()=>coordinators[1].proposal([{kind:'debit',proof:a}]));
 assert.throws(()=>coordinators[0].proposal([{kind:'debit',proof:tx(0,1,1001)}]));
 const bad=structuredClone(a);bad.intent.amount++;assert.throws(()=>coordinators[0].proposal([{kind:'debit',proof:bad}]));
 const before=sum(),start=performance.now();
 const east=certify(0,[{kind:'debit',proof:a},{kind:'debit',proof:tx(0,3,50)}]);
 const north=certify(2,[{kind:'debit',proof:tx(2,0,100)}]);
 assert.equal(sum(),before-400);
 const r=east.results[0],n=north.results[0];assert.equal(lab.verifyDebit(r).destination,'demo-west');
 assert.throws(()=>coordinators[0].proposal([{kind:'debit',proof:b}]));
 assert.throws(()=>coordinators[2].proposal([{kind:'claim',receipt:r}]));
 const bogus=structuredClone(r);bogus.certificate.commit.votes.pop();assert.throws(()=>coordinators[1].proposal([{kind:'claim',receipt:bogus}]));
 const wrong=structuredClone(r);wrong.siblings[0]='f'.repeat(64);assert.throws(()=>coordinators[1].proposal([{kind:'claim',receipt:wrong}]));
 const changed=structuredClone(r);changed.proof.intent.payee='demo-carol';assert.throws(()=>lab.verifyDebit(changed));
 assert.throws(()=>coordinators[1].proposal([{kind:'claim',receipt:r},{kind:'claim',receipt:r}]));
 certify(1,[{kind:'claim',receipt:r}]);assert.equal(sum(),before-100);
 certify(0,[{kind:'claim',receipt:n}]);assert.equal(sum(),before);
 assert.throws(()=>coordinators[1].proposal([{kind:'claim',receipt:r}]));
 assert.throws(()=>coordinators[0].proposal([{kind:'debit',proof:a}]));
 assert.deepEqual(coordinators.map(s=>s.snapshot().balances),[{'demo-alice':750,'demo-dan':1050},{'demo-bob':1300},{'demo-carol':900}]);
 t.diagnostic('SHARDED_PAY_V1 '+JSON.stringify({shards:3,authorities:48,activePerShard:11,blocks:4,ms:performance.now()-start,initial:before,final:sum(),simulationOnly:true}));
});
