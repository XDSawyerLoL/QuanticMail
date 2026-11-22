import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync,sign,randomBytes} from 'node:crypto';
import {mkdtempSync,realpathSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {openShardedPayLab} from '../lib/quantic/pay-sharded-lab.mjs';
import {openQuorumPayRoundLab} from '../lib/quantic/pay-quorum-gated-signing-lab.mjs';
import {openQuorumFenceLab} from '../lib/quantic/pay-quorum-fence-lab.mjs';
const sha=b=>createHash('sha256').update(b).digest('hex');
function key(type='ed25519'){
 const cl=type==='ec'?generateKeyPairSync('ec',{namedCurve:'prime256v1'}):generateKeyPairSync(type),pq=generateKeyPairSync('ml-dsa-65');
 const a=cl.publicKey.export({type:'spki',format:'der'}),b=pq.publicKey.export({type:'spki',format:'der'});
 return {cl,pq,pub:{pin:sha(a),pqPin:sha(b),publicKey:a.toString('base64url'),pqPublicKey:b.toString('base64url')}};
}
const credentials=k=>({authorityPin:k.pub.pin,classicalPrivateKey:k.cl.privateKey,pqPrivateKey:k.pq.privateKey});
test('real shard votes require fresh three-of-four local grants and actual final certificate',{skip:process.platform!=='linux',timeout:60000},t=>{
 const root=realpathSync(mkdtempSync(join(tmpdir(),'quantic-gated-'))),witnesses=[],signers=[];
 try{
  const east='demo-east',west='demo-west',keys=Array.from({length:16},()=>key()),other=Array.from({length:16},()=>key()),wk=Array.from({length:4},()=>key()),alice=key('ec'),bob=key('ec'),members=keys.map(k=>k.pub);
  const config={shards:[{id:east,authorities:members},{id:west,authorities:other.map(k=>k.pub)}],wallets:[{id:'demo-alice',shard:east,initial:1000,publicKey:alice.pub.publicKey,pqPublicKey:alice.pub.pqPublicKey},{id:'demo-bob',shard:west,initial:0,publicKey:bob.pub.publicKey,pqPublicKey:bob.pub.pqPublicKey}]};
  const lab=openShardedPayLab(config),source=lab.openShard(east),committee=sha(Buffer.from(JSON.stringify(['quantic-handoff-roster/lab/v1',members.map(m=>[m.pin,m.pqPin]).sort((a,b)=>a[0]<b[0]?-1:1)])));
  const fenceConfig={network:lab.network,shard:east,initialCommittee:committee,genesisRoot:source.snapshot().root,witnesses:wk.map(k=>k.pub)};
  const anchor={epoch:0,height:0,root:fenceConfig.genesisRoot,committee,tip:'0'.repeat(64)};
  const gate=openQuorumPayRoundLab({fenceConfig,anchor,authorities:members,validateCandidate:ops=>source.proposal(ops).value}),fence=openQuorumFenceLab(fenceConfig);
  for(let i=0;i<4;i++)witnesses.push(fence.openWitness({directory:join(root,String(i)),credentials:{pin:wk[i].pub.pin,classicalPrivateKey:wk[i].cl.privateKey,pqPrivateKey:wk[i].pq.privateKey},createNew:true,verifyDecision:gate.verifyDecision}));
  function debit(amount){const intent={network:lab.network,payer:'demo-alice',payee:'demo-bob',amount,nonce:randomBytes(32).toString('hex')},b=lab.intentBytes(intent);return [{kind:'debit',proof:{intent,signature:sign('sha256',b,{key:alice.cl.privateKey,dsaEncoding:'ieee-p1363'}).toString('base64url'),pqSignature:sign(null,b,alice.pq.privateKey).toString('base64url')}}];}
  const operations=debit(100),value=source.proposal(operations).value,conflict=debit(200),alternate=source.proposal(conflict).value;
  assert.equal(gate.scope,source.proposal(operations).scope);
  const disabled={grant(){throw Error('unavailable');}};
  const limited=gate.openAuthority({credentials:credentials(keys[15]),witnessClients:[witnesses[0],witnesses[1],disabled]});signers.push(limited);
  assert.throws(()=>limited.prepare({value:alternate,candidate:operations}));
  assert.equal(witnesses[0].status().mode,'idle');
  assert.throws(()=>limited.prepare({value,candidate:operations}));
  assert.equal(witnesses[0].status().pending,value);
  const started=performance.now();
  for(const k of keys.slice(0,11))signers.push(gate.openAuthority({credentials:credentials(k),witnessClients:witnesses.slice(0,3)}));
  const active=signers.slice(1),prepared={scope:gate.scope,round:0,value,votes:active.map(s=>s.prepare({value,candidate:operations}))};
  const rival=gate.openAuthority({credentials:credentials(keys[14]),witnessClients:[witnesses[1],witnesses[2],witnesses[3]]});signers.push(rival);
  assert.throws(()=>rival.prepare({value:alternate,candidate:conflict}));
  assert.throws(()=>active[0].commit({...prepared,votes:prepared.votes.slice(0,10)}));
  const certificate={prepared,commit:{scope:gate.scope,round:0,value,votes:active.map(s=>s.commit(prepared))}};
  const request=gate.request(value),grants=witnesses.slice(0,3).map(w=>w.grant(request));
  assert.throws(()=>witnesses[0].complete(request,grants,{prepared,commit:{...certificate.commit,votes:certificate.commit.votes.slice(0,10)}}));
  for(const w of witnesses)w.complete(request,grants,certificate);
  // Fresh local calls to the witnesses reject the old epoch/height even
  // before the coordinator installs its certified block.
  assert.throws(()=>active[0].commit(prepared));assert.throws(()=>limited.prepare({value,candidate:operations}));
  const receipts=source.finalize(operations,certificate);
  assert.equal(source.snapshot().balances['demo-alice'],900);assert.equal(lab.verifyDebit(receipts[0]).destination,west);
  assert.ok(witnesses.every(w=>w.status().height===1&&w.status().root===value));
  t.diagnostic('QUORUM_GATED_PAY_V1 '+JSON.stringify({witnesses:4,activeFinancialAuthorities:11,elapsedMs:performance.now()-started,actualLedgerCertificate:true,simulationOnly:true}));
 }finally{for(const s of signers)s.close();for(const w of witnesses)w.close();rmSync(root,{recursive:true,force:true});}
});
