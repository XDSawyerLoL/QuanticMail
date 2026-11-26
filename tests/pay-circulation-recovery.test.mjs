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
test('genuine 2-2 durable split remains safely blocked, no time-based or operator unlock',{skip:process.platform!=='linux'},()=>{
 const root=realpathSync(mkdtempSync(join(tmpdir(),'circulation-split-')));
 const ids=['demo-alice','demo-bob','demo-shop'],wallets=ids.map(()=>pair('ec')),witnesses=Array.from({length:4},()=>pair('ed25519'));
 const config={wallets:ids.map((id,i)=>({id,initialCents:i===0?10000:0,...pub(wallets[i])})),witnesses:witnesses.map(pub)};
 const lab=createCirculationLab(config),stores=[];let now=1000000;
 const opts=witnesses.map((w,i)=>({directory:join(root,'witness-'+i),config,authorityPin:pub(w).pin,classicalPrivateKey:w.cl.privateKey,pqPrivateKey:w.pq.privateKey,clock:()=>now}));
 function proposal(payee){
  const intent=lab.prepare([],{payer:ids[0],payee,cents:7500,nonce:randomBytes(32).toString('hex'),now}),k=wallets[0],b=lab.transcript(intent);
  return {intent,signature:sign('sha256',b,{key:k.cl.privateKey,dsaEncoding:'ieee-p1363'}).toString('base64url'),pqSignature:sign(null,b,k.pq.privateKey).toString('base64url')};
 }
 try{
  for(const o of opts)stores.push(openCirculationWitness({...o,createNew:true}));
  const a=proposal(ids[1]),b=proposal(ids[2]),decidedAt=now;
  for(let i=0;i<4;i++){stores[i].vote({proof:i<2?a:b,decidedAt});stores[i].close();stores[i]=openCirculationWitness(opts[i]);}
  const recover=()=>recoverCirculationCertificate({config,records:[],reports:stores.map(s=>s.pendingVote())});
  assert.equal(recover().state,'blocked-no-certificate');assert.deepEqual(recover().groupSizes,[2,2]);
  assert.throws(()=>stores[0].commit({proof:a,decidedAt,votes:stores.slice(0,2).map(s=>s.pendingVote().vote)}));
  now+=130000;assert.equal(recover().state,'blocked-no-certificate');
  for(let i=0;i<4;i++){assert.throws(()=>stores[i].vote({proof:i<2?b:a,decidedAt:now}));assert.equal(stores[i].status().sequence,0);}
  assert.equal(stores[0].status().balances[ids[0]],10000);
 }finally{for(const s of stores)s.close();rmSync(root,{recursive:true,force:true});}
});
