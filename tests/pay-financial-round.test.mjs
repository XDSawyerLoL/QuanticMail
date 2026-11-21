import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,createHash,sign,randomBytes} from 'node:crypto';
import {mkdtempSync,realpathSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createCirculationLab} from '../lib/quantic/pay-circulation-lab.mjs';
import {openFinancialRound} from '../lib/quantic/pay-financial-round.mjs';
import {openPersistentPayRound} from '../lib/quantic/pay-round-store.mjs';
const sha=b=>createHash('sha256').update(b).digest('hex');
const spki=k=>k.publicKey.export({type:'spki',format:'der'});
const pair=type=>({cl:type==='ec'?generateKeyPairSync('ec',{namedCurve:'prime256v1'}):generateKeyPairSync(type),pq:generateKeyPairSync('ml-dsa-65')});
const pub=k=>({pin:sha(spki(k.cl)),publicKey:spki(k.cl).toString('base64url'),pqPin:sha(spki(k.pq)),pqPublicKey:spki(k.pq).toString('base64url')});
test('signed conflicting financial intents enter persistent 2-2 round recovery and yield a single certified hypothetical balance',{skip:process.platform!=='linux'},()=>{
 const root=realpathSync(mkdtempSync(join(tmpdir(),'pay-financial-round-'))),now=1000000;
 const ids=['demo-alice','demo-bob','demo-shop'],wallets=ids.map(()=>pair('ec')),witnesses=Array.from({length:4},()=>pair('ed25519'));
 const config={wallets:ids.map((id,i)=>({id,initialCents:i===0?10000:0,...pub(wallets[i])})),witnesses:witnesses.map(pub)};
 const circulation=createCirculationLab(config),stores=[];
 function proposal(payee){
  const intent=circulation.prepare([],{payer:ids[0],payee,cents:7500,nonce:randomBytes(32).toString('hex'),now}),k=wallets[0],raw=circulation.transcript(intent);
  return {intent,signature:sign('sha256',raw,{key:k.cl.privateKey,dsaEncoding:'ieee-p1363'}).toString('base64url'),pqSignature:sign(null,raw,k.pq.privateKey).toString('base64url')};
 }
 const a=proposal(ids[1]),b=proposal(ids[2]),params={config,records:[],proposals:[a,b],admissionTime:now};
 try{
  assert.throws(()=>openFinancialRound({...params,proposals:[{...a,intent:{...a.intent,cents:7499}},b]}));
  assert.throws(()=>openFinancialRound({...params,admissionTime:now+120000}));
  assert.throws(()=>openFinancialRound({...params,proposals:[a,a]}));
  const lab=openFinancialRound(params),[alpha,beta]=lab.candidates().map(c=>c.value);
  assert.notEqual(alpha,beta);
  assert.equal(openFinancialRound({...params,proposals:[b,a]}).scope,lab.scope);
  const opts=witnesses.map((w,i)=>({directory:join(root,'witness-'+i),config:lab.roundConfig(),authorityPin:config.witnesses[i].pin,classicalPrivateKey:w.cl.privateKey,pqPrivateKey:w.pq.privateKey}));
  for(const o of opts)stores.push(openPersistentPayRound({...o,createNew:true}));
  for(let i=0;i<4;i++){stores[i].prepare({round:0,value:i<2?alpha:beta});stores[i].close();stores[i]=openPersistentPayRound(opts[i]);}
  assert.throws(()=>stores[0].prepare({round:0,value:beta}));
  const vc={scope:lab.scope,round:1,reports:stores.map(s=>s.changeView(1)).slice(0,3)};
  assert.equal(lab.selectView(vc).requiredValue,null);
  assert.throws(()=>stores[0].prepare({round:1,value:'c'.repeat(64),viewCertificate:vc}));
  const prepare={scope:lab.scope,round:1,value:beta,votes:stores.slice(0,3).map(s=>s.prepare({round:1,value:beta,viewCertificate:vc}))};
  const commit={scope:lab.scope,round:1,value:beta,votes:stores.slice(0,3).map(s=>s.commit(prepare))};
  const cert={prepared:prepare,commit};
  assert.throws(()=>lab.project({prepared:prepare,commit:{...commit,votes:commit.votes.slice(0,2)}}));
  assert.throws(()=>lab.project({prepared:prepare,commit:{...commit,value:alpha}}));
  assert.throws(()=>openFinancialRound({...params,proposals:[b]}).project(cert));
  const result=lab.project(cert);
  assert.deepEqual(result.balances,{'demo-alice':2500,'demo-bob':0,'demo-shop':7500});
  assert.equal(result.totalCents,10000);assert.equal(result.ledgerCommitted,false);assert.equal(result.realPaymentAuthorized,false);
  for(const s of stores)s.learn(cert);
  assert.equal(circulation.snapshot([]).balances['demo-alice'],10000);
  stores[0].close();stores[0]=openPersistentPayRound(opts[0]);assert.equal(stores[0].status().finalValue,beta);
 }finally{for(const s of stores)s.close();rmSync(root,{recursive:true,force:true});}
});
