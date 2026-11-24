import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,createHash,sign,randomBytes} from 'node:crypto';
import {mkdtempSync,realpathSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createCirculationLab} from '../lib/quantic/pay-circulation-lab.mjs';
import {openCirculationWitness} from '../lib/quantic/pay-circulation-witness-store.mjs';
import {recoverCirculationCertificate} from '../lib/quantic/pay-circulation-recovery.mjs';
const sha=b=>createHash('sha256').update(b).digest('hex');
const spki=k=>k.publicKey.export({type:'spki',format:'der'});
const pair=type=>({cl:type==='ec'?generateKeyPairSync('ec',{namedCurve:'prime256v1'}):generateKeyPairSync(type),pq:generateKeyPairSync('ml-dsa-65')});
const pub=k=>({pin:sha(spki(k.cl)),publicKey:spki(k.cl).toString('base64url'),pqPin:sha(spki(k.pq)),pqPublicKey:spki(k.pq).toString('base64url')});
test('durable vote locks reject conflicting proposals after restart, commit exact quorum and catch up nonvoter',{skip:process.platform!=='linux'},()=>{
 const root=realpathSync(mkdtempSync(join(tmpdir(),'circulation-lock-')));
 const ids=['demo-alice','demo-bob','demo-shop'],wallets=ids.map(()=>pair('ec')),witnesses=Array.from({length:4},()=>pair('ed25519'));
 const config={wallets:ids.map((id,i)=>({id,initialCents:i===0?10000:0,...pub(wallets[i])})),witnesses:witnesses.map(pub)};
 const lab=createCirculationLab(config),stores=[],records=[];let now=1000000;
 const opts=witnesses.map((w,i)=>({directory:join(root,'witness-'+i),config,authorityPin:pub(w).pin,classicalPrivateKey:w.cl.privateKey,pqPrivateKey:w.pq.privateKey,clock:()=>now}));
 function proof(payer,payee,cents){
  const intent=lab.prepare(records,{payer,payee,cents,nonce:randomBytes(32).toString('hex'),now}),k=wallets[ids.indexOf(payer)],b=lab.transcript(intent);
  return {intent,signature:sign('sha256',b,{key:k.cl.privateKey,dsaEncoding:'ieee-p1363'}).toString('base64url'),pqSignature:sign(null,b,k.pq.privateKey).toString('base64url')};
 }
 try{
  for(const o of opts)stores.push(openCirculationWitness({...o,createNew:true}));
  const a=proof(ids[0],ids[1],7500),b=proof(ids[0],ids[2],7500),decidedAt=now;
  const first=stores[0].vote({proof:a,decidedAt});
  stores[0].close();stores[0]=openCirculationWitness(opts[0]);
  assert.equal(stores[0].status().pendingSequence,1);
  assert.deepEqual(stores[0].vote({proof:a,decidedAt}),first);
  assert.throws(()=>stores[0].vote({proof:b,decidedAt}));
  assert.throws(()=>stores[0].vote({proof:a,decidedAt:decidedAt-1}));
  const votes=[first,...stores.slice(1,3).map(s=>s.vote({proof:a,decidedAt}))];
  const r={proof:a,decidedAt,votes};
  stores[3].vote({proof:b,decidedAt});
  const partial=recoverCirculationCertificate({config,records,reports:[stores[0].pendingVote(),stores[1].pendingVote(),stores[3].pendingVote()]});
  assert.equal(partial.state,'blocked-no-certificate');assert.deepEqual(partial.groupSizes,[2,1]);
  assert.equal(recoverCirculationCertificate({config,records,reports:[stores[0].pendingVote(),stores[0].pendingVote()]}).state,'duplicate-or-equivocating-report');
  assert.throws(()=>stores[0].commit({...r,votes:votes.slice(0,2)}));
  now+=130000;
  assert.throws(()=>stores[0].vote({proof:a,decidedAt}));
  // An expired vote lock is not released, but the exact existing certificate
  // can be applied as historical evidence without issuing another vote.
  const recovered=recoverCirculationCertificate({config,records,reports:stores.map(s=>s.pendingVote())});
  assert.equal(recovered.state,'certificate-recovered');assert.deepEqual(recovered.certificate,r);
  for(const s of stores)s.commit(recovered.certificate);
  records.push(r);assert.deepEqual(stores[3].status().balances,lab.snapshot(records).balances);
  stores[3].close();stores[3]=openCirculationWitness(opts[3]);
  assert.equal(stores[3].status().sequence,1);assert.equal(stores[3].pendingVote(),null);
  stores[1].close();stores[1]=openCirculationWitness(opts[1]);
  assert.equal(stores[1].status().sequence,1);assert.equal(stores[1].status().pendingSequence,null);
  assert.throws(()=>stores[1].vote({proof:b,decidedAt:now}));
  const next=proof(ids[1],ids[2],7000),at=now;
  const rr={proof:next,decidedAt:at,votes:[0,1,3].map(i=>stores[i].vote({proof:next,decidedAt:at}))};
  for(const s of stores)s.commit(rr);
  records.push(rr);
  assert.deepEqual(stores[0].status().balances,{'demo-alice':2500,'demo-bob':500,'demo-shop':7000});
  assert.equal(stores[0].commit(rr).sequence,2);
  assert.throws(()=>openCirculationWitness({...opts[0],createNew:true}));
 }finally{for(const s of stores)s.close();rmSync(root,{recursive:true,force:true});}
});
