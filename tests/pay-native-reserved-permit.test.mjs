import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,createHash,randomBytes,sign} from 'node:crypto';
import {realpathSync,mkdtempSync,rmSync} from 'node:fs';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {openShardedPayLab} from '../lib/quantic/pay-sharded-lab.mjs';
import {openNativePayPermitLab} from '../lib/quantic/pay-native-permit-lab.mjs';
const hash=x=>createHash('sha256').update(JSON.stringify(x)).digest('hex');
const sha=x=>createHash('sha256').update(x).digest('hex');
function key(type='ed25519'){const cl=type==='ec'?generateKeyPairSync('ec',{namedCurve:'prime256v1'}):generateKeyPairSync(type),pq=generateKeyPairSync('ml-dsa-65');const a=cl.publicKey.export({type:'spki',format:'der'}),b=pq.publicKey.export({type:'spki',format:'der'});return {cl,pq,pub:{pin:sha(a),pqPin:sha(b),publicKey:a.toString('base64url'),pqPublicKey:b.toString('base64url')}};}
const creds=k=>({authorityPin:k.pub.pin,classicalPrivateKey:k.cl.privateKey,pqPrivateKey:k.pq.privateKey});
test('a native Pay permit is issued only against the specific certified and still-held reservation',{skip:process.platform!=='linux',timeout:60000},t=>{
 const root=realpathSync(mkdtempSync(join(tmpdir(),'quantic-reserved-permit-'))),stores=[];
 try{
  const east='demo-east',west='demo-west',keys=Array.from({length:16},()=>key()),others=Array.from({length:16},()=>key()),alice=key('ec'),shop=key('ec');
  const cfg={shards:[{id:east,authorities:keys.map(k=>k.pub)},{id:west,authorities:others.map(k=>k.pub)}],wallets:[{id:'demo-alice',shard:east,initial:1000,publicKey:alice.pub.publicKey,pqPublicKey:alice.pub.pqPublicKey},{id:'demo-shop',shard:west,initial:0,publicKey:shop.pub.publicKey,pqPublicKey:shop.pub.pqPublicKey}]};
  const lab=openShardedPayLab(cfg,{reservationsEnabled:true}),source=lab.openShard(east);
  const nonce=randomBytes(32).toString('hex'),request={network:lab.network,payer:'demo-alice',payee:'demo-shop',amount:200,nonce},data=lab.intentBytes(request);
  const signed={intent:request,signature:sign('sha256',data,{key:alice.cl.privateKey,dsaEncoding:'ieee-p1363'}).toString('base64url'),pqSignature:sign(null,data,alice.pq.privateKey).toString('base64url')};
  const reservationId=hash(['quantic-shard-id/v1',data.toString('hex')]);
  const reserve=[{kind:'reserve',proof:signed}],draft=source.proposal(reserve),signers=keys.slice(0,11).map(k=>source.openAuthority(creds(k)));
  const prepared={scope:draft.scope,round:0,value:draft.value,votes:signers.map(s=>s.prepare(reserve))};
  source.finalize(reserve,{prepared,commit:{scope:draft.scope,round:0,value:draft.value,votes:signers.map(s=>s.commit(prepared))}});
  const cp=source.checkpoint(),s=source.snapshot(),anchor={network:lab.network,shard:east,height:s.height,root:s.root};
  assert.equal(cp.balances['demo-alice'],800);
  const labPermit=openNativePayPermitLab({config:cfg,checkpoint:cp,anchor,payer:'demo-alice',reservationId});
  const now=Date.now(),intent={Payee:'demo-shop',Cents:200,Nonce:nonce,Issued:now,Expires:now+120000};
  assert.throws(()=>labPermit.candidate({...intent,Cents:201},now));
  assert.throws(()=>labPermit.candidate({...intent,Nonce:randomBytes(32).toString('hex')},now));
  assert.throws(()=>openNativePayPermitLab({config:cfg,checkpoint:cp,anchor,payer:'demo-alice',reservationId:'f'.repeat(64)}));
  assert.throws(()=>openNativePayPermitLab({config:cfg,checkpoint:cp,anchor:{...anchor,root:'f'.repeat(64)},payer:'demo-alice',reservationId}));
  const candidate=labPermit.candidate(intent,now);
  for(let i=0;i<11;i++)stores.push(labPermit.openAuthority({directory:join(root,String(i)),createNew:true,credentials:creds(keys[i]),clock:()=>now}));
  const votes={scope:labPermit.scope,round:0,value:candidate.value,votes:stores.map(n=>n.prepare(intent))};
  const certificate={prepared:votes,commit:{scope:labPermit.scope,round:0,value:candidate.value,votes:stores.map(n=>n.commit(intent,votes))}};
  const permit=labPermit.permit(intent,certificate,now);
  assert.equal(permit.reservationId,reservationId);
  assert.equal(permit.available,200);
  assert.equal(permit.realPaymentAuthorized,false);
  assert.throws(()=>labPermit.permit({...intent,Nonce:'f'.repeat(64)},certificate,now));
  assert.throws(()=>labPermit.permit(intent,{...certificate,prepared:{...certificate.prepared,votes:certificate.prepared.votes.slice(0,10)}},now));
  t.diagnostic('NATIVE_RESERVED_PERMIT_V1 '+JSON.stringify({reserved:200,available:800,permitAuthorities:11,spentNonceBound:true,simulationOnly:true}));
 }finally{for(const store of stores)store.close();rmSync(root,{recursive:true,force:true});}
});
