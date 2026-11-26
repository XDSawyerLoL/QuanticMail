import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,createHash,randomBytes,sign} from 'node:crypto';
import {mkdtempSync,realpathSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {openShardedPayLab} from '../lib/quantic/pay-sharded-lab.mjs';
import {openNativePayPermitLab} from '../lib/quantic/pay-native-permit-lab.mjs';
const sha=b=>createHash('sha256').update(b).digest('hex');
function key(type){
 const cl=type==='ec'?generateKeyPairSync('ec',{namedCurve:'prime256v1'}):generateKeyPairSync(type),pq=generateKeyPairSync('ml-dsa-65');
 const a=cl.publicKey.export({type:'spki',format:'der'}),b=pq.publicKey.export({type:'spki',format:'der'});
 return {cl,pq,pub:{pin:sha(a),pqPin:sha(b),publicKey:a.toString('base64url'),pqPublicKey:b.toString('base64url')}};
}
const creds=k=>({authorityPin:k.pub.pin,classicalPrivateKey:k.cl.privateKey,pqPrivateKey:k.pq.privateKey});
test('native permit validates certified balance and locks competing intents in a durable round',{skip:process.platform!=='linux',timeout:60000},t=>{
 const dir=realpathSync(mkdtempSync(join(tmpdir(),'quantic-native-permit-'))),nodes=[];
 try{
  const east='demo-east',west='demo-west',keys=Array.from({length:16},()=>key('ed25519')),other=Array.from({length:16},()=>key('ed25519')),a=key('ec'),b=key('ec'),payer='demo-alice';
  const config={shards:[{id:east,authorities:keys.map(k=>k.pub)},{id:west,authorities:other.map(k=>k.pub)}],wallets:[{id:payer,shard:east,initial:1000,publicKey:a.pub.publicKey,pqPublicKey:a.pub.pqPublicKey},{id:'demo-shop',shard:west,initial:0,publicKey:b.pub.publicKey,pqPublicKey:b.pub.pqPublicKey}]};
  const lab=openShardedPayLab(config),source=lab.openShard(east);
  const spentNonce=randomBytes(32).toString('hex'),i={network:lab.network,payer,payee:'demo-shop',amount:100,nonce:spentNonce},bytes=lab.intentBytes(i);
  const ops=[{kind:'debit',proof:{intent:i,signature:sign('sha256',bytes,{key:a.cl.privateKey,dsaEncoding:'ieee-p1363'}).toString('base64url'),pqSignature:sign(null,bytes,a.pq.privateKey).toString('base64url')}}];
  const proposal=source.proposal(ops),voters=keys.slice(0,11).map(k=>source.openAuthority(creds(k))),prepared={scope:proposal.scope,round:0,value:proposal.value,votes:voters.map(v=>v.prepare(ops))};
  source.finalize(ops,{prepared,commit:{scope:proposal.scope,round:0,value:proposal.value,votes:voters.map(v=>v.commit(prepared))}});
  const checkpoint=source.checkpoint(),snapshot=source.snapshot(),anchor={network:lab.network,shard:east,height:snapshot.height,root:snapshot.root};
  const now=Date.now(),clock=()=>now,open=()=>openNativePayPermitLab({config,checkpoint,anchor,payer}),permit=open(),intent={Payee:'demo-shop',Cents:200,Nonce:randomBytes(32).toString('hex'),Issued:now,Expires:now+120000};
  assert.throws(()=>permit.candidate({...intent,Cents:901},now));
  assert.throws(()=>permit.candidate({...intent,Nonce:spentNonce},now));
  assert.throws(()=>permit.candidate(intent,intent.Expires));
  assert.throws(()=>openNativePayPermitLab({config,checkpoint,anchor:{...anchor,root:'a'.repeat(64)},payer}));
  const candidate=permit.candidate(intent,now),start=performance.now();
  for(let n=0;n<11;n++)nodes.push(open().openAuthority({directory:join(dir,String(n)),createNew:true,credentials:creds(keys[n]),clock}));
  const pre={scope:permit.scope,round:0,value:candidate.value,votes:nodes.map(n=>n.prepare(intent))};
  nodes[0].close();nodes[0]=open().openAuthority({directory:join(dir,'0'),credentials:creds(keys[0]),clock});
  assert.deepEqual(nodes[0].prepare(intent),pre.votes[0]);
  assert.throws(()=>nodes[0].prepare({...intent,Cents:201}));
  const certificate={prepared:pre,commit:{scope:permit.scope,round:0,value:candidate.value,votes:nodes.map(n=>n.commit(intent,pre))}};
  const proof=permit.permit(intent,certificate,now);assert.equal(proof.available,900);assert.equal(proof.intentDigest,candidate.digest);assert.equal(proof.realPaymentAuthorized,false);
  assert.throws(()=>permit.permit({...intent,Cents:201},certificate,now));
  assert.throws(()=>permit.permit(intent,{...certificate,commit:{...certificate.commit,votes:certificate.commit.votes.slice(0,10)}},now));
  t.diagnostic('NATIVE_PAY_PERMIT_V1 '+JSON.stringify({authorities:16,active:11,available:900,requested:200,certificateBytes:Buffer.byteLength(JSON.stringify(proof)),ms:performance.now()-start,simulationOnly:true}));
 }finally{for(const n of nodes)n.close();rmSync(dir,{recursive:true,force:true});}
});
