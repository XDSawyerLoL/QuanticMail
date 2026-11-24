import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,createHash,sign,randomBytes} from 'node:crypto';
import {createCirculationLab} from '../lib/quantic/pay-circulation-lab.mjs';
const sha=b=>createHash('sha256').update(b).digest('hex');
const spki=k=>k.publicKey.export({type:'spki',format:'der'});
const pair=type=>({
 classical:type==='ec'?generateKeyPairSync('ec',{namedCurve:'prime256v1'}):generateKeyPairSync(type),
 pq:generateKeyPairSync('ml-dsa-65')
});
function pub(k){return {pin:sha(spki(k.classical)),publicKey:spki(k.classical).toString('base64url'),pqPin:sha(spki(k.pq)),pqPublicKey:spki(k.pq).toString('base64url')};}
test('synthetic value circulates between individually pinned wallets, three hybrid votes required on every state transition',()=>{
 const now=1000000,ids=['demo-alice','demo-bob','demo-shop'];
 const keys=ids.map(()=>pair('ec')),witnesses=Array.from({length:4},()=>pair('ed25519'));
 const config={wallets:ids.map((id,i)=>({id,initialCents:i===0?10000:0,...pub(keys[i])})),witnesses:witnesses.map(pub)};
 const lab=createCirculationLab(config),records=[],retained=witnesses.map(()=>[]);
 function proposal(payer,payee,cents){
  const intent=lab.prepare(records,{payer,payee,cents,nonce:randomBytes(32).toString('hex'),now});
  const k=keys[ids.indexOf(payer)],b=lab.transcript(intent);
  return {intent,signature:sign('sha256',b,{key:k.classical.privateKey,dsaEncoding:'ieee-p1363'}).toString('base64url'),pqSignature:sign(null,b,k.pq.privateKey).toString('base64url')};
 }
 function vote(proof,i){const w=witnesses[i];return lab.attest({retainedRecords:retained[i],proof,decidedAt:now,authorityPin:pub(w).pin,classicalPrivateKey:w.classical.privateKey,pqPrivateKey:w.pq.privateKey,now});}
 function commit(proof){
  const record={proof,decidedAt:now,votes:[0,1,2,3].map(i=>vote(proof,i))};
  assert.throws(()=>lab.confirm(records,{...record,votes:record.votes.slice(0,2)},now));
  assert.throws(()=>lab.confirm(records,{...record,votes:[record.votes[0],record.votes[0],record.votes[1]]},now));
  assert.throws(()=>lab.confirm(records,{...record,votes:record.votes.slice(0,3).map(v=>({...v,pqSignature:undefined}))},now));
  const result=lab.confirm(records,record,now);assert.equal(result.totalCents,10000);
  records.push(record);for(const h of retained)h.push(structuredClone(record));return record;
 }
 assert.throws(()=>proposal('demo-bob','demo-alice',1));
 const p=proposal('demo-alice','demo-bob',7500);
 const alternative=proposal('demo-alice','demo-shop',7500);
 const r=commit(p);
 assert.throws(()=>vote(alternative,0));
 assert.throws(()=>lab.confirm(records,r,now));
 const q=proposal('demo-bob','demo-shop',7000);
 assert.throws(()=>vote({...q,intent:{...q.intent,cents:7001}},0));
 assert.throws(()=>vote({...q,intent:{...q.intent,payee:'demo-alice'}},0));
 commit(q);commit(proposal('demo-shop','demo-alice',6000));
 assert.deepEqual(lab.snapshot(records).balances,{'demo-alice':8500,'demo-bob':500,'demo-shop':1000});
 assert.deepEqual(createCirculationLab(config).snapshot(structuredClone(records)),lab.snapshot(records));
 assert.throws(()=>proposal('demo-shop','demo-alice',1001));
 assert.throws(()=>lab.snapshot([records[0],records[2]]));
 assert.throws(()=>lab.confirm([],r,now+120000));
 assert.throws(()=>createCirculationLab({...config,witnesses:[config.witnesses[0],config.witnesses[0],...config.witnesses.slice(2)]}));
});
