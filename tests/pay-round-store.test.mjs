import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,createHash} from 'node:crypto';
import {mkdtempSync,realpathSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {DatabaseSync} from 'node:sqlite';
import {openPersistentPayRound} from '../lib/quantic/pay-round-store.mjs';
import {createPayRoundLab} from '../lib/quantic/pay-round-lab.mjs';
const sha=b=>createHash('sha256').update(b).digest('hex');
const spki=k=>k.publicKey.export({type:'spki',format:'der'});
function fixture(){
 const keys=Array.from({length:4},()=>({cl:generateKeyPairSync('ed25519'),pq:generateKeyPairSync('ml-dsa-65')}));
 const authorities=keys.map(k=>({pin:sha(spki(k.cl)),publicKey:spki(k.cl).toString('base64url'),pqPin:sha(spki(k.pq)),pqPublicKey:spki(k.pq).toString('base64url')}));
 const config={network:'a'.repeat(64),height:1,previousRoot:'b'.repeat(64),authorities};
 const lab=createPayRoundLab(config),root=realpathSync(mkdtempSync(join(tmpdir(),'round-persistent-')));
 const opts=keys.map((k,i)=>({directory:join(root,'witness-'+i),config,authorityPin:authorities[i].pin,classicalPrivateKey:k.cl.privateKey,pqPrivateKey:k.pq.privateKey}));
 const stores=[];
 const reopen=i=>{stores[i]?.close();stores[i]=openPersistentPayRound(opts[i]);};
 const close=()=>{for(const s of stores)s.close();rmSync(root,{recursive:true,force:true});};
 return {lab,opts,stores,reopen,close};
}
test('persistent view change survives restart at every phase, refuses inconsistent votes and returns exact stored signatures',{skip:process.platform!=='linux'},()=>{
 const {lab,opts,stores,reopen,close}=fixture(),a='demo-alpha',b='demo-beta';
 try{
  assert.throws(()=>openPersistentPayRound(opts[0]));
  for(const o of opts)stores.push(openPersistentPayRound({...o,createNew:true}));
  const old=stores.map((s,i)=>s.prepare({round:0,value:i<2?a:b}));
  for(let i=0;i<4;i++)reopen(i);
  assert.deepEqual(stores[0].prepare({round:0,value:a}),old[0]);assert.equal(stores[0].status().journalCount,1);
  assert.throws(()=>stores[0].prepare({round:0,value:b}));
  const reports=stores.map(s=>s.changeView(1));
  for(let i=0;i<4;i++)reopen(i);
  assert.deepEqual(stores[0].changeView(1),reports[0]);assert.throws(()=>stores[0].prepare({round:0,value:a}));
  const vc={scope:lab.scope,round:1,reports:reports.slice(0,3)};
  const p={scope:lab.scope,round:1,value:b,votes:stores.slice(0,3).map(s=>s.prepare({round:1,value:b,viewCertificate:vc}))};
  const commit={scope:lab.scope,round:1,value:b,votes:stores.slice(0,3).map(s=>s.commit(p))};
  for(let i=0;i<4;i++)reopen(i);
  assert.deepEqual(stores[0].commit(p),commit.votes[0]);assert.equal(stores[0].status().preparedValue,b);
  const c={prepared:p,commit};
  for(const s of stores)s.learn(c);
  reopen(0);assert.equal(stores[0].status().finalValue,b);
  assert.throws(()=>stores[0].changeView(2));
  assert.throws(()=>openPersistentPayRound({...opts[0],createNew:true}));
  stores[0].close();const db=new DatabaseSync(join(opts[0].directory,'round.sqlite'));
  try{db.exec("UPDATE events SET body='{}' WHERE seq=1");}finally{db.close();}
  assert.throws(()=>openPersistentPayRound(opts[0]));
 }finally{close();}
});
test('persisted highest prepare certificate survives withheld commit and forces safe new round',{skip:process.platform!=='linux'},()=>{
 const {lab,opts,stores,reopen,close}=fixture(),a='demo-alpha',b='demo-beta';
 try{
  for(const o of opts)stores.push(openPersistentPayRound({...o,createNew:true}));
  const p={scope:lab.scope,round:0,value:a,votes:stores.slice(0,3).map(s=>s.prepare({round:0,value:a}))};
  const c={scope:lab.scope,round:0,value:a,votes:stores.slice(0,3).map(s=>s.commit(p))};
  for(let i=0;i<4;i++)reopen(i);
  const reports=stores.map(s=>s.changeView(1));reopen(1);
  const vc={scope:lab.scope,round:1,reports:[reports[1],reports[2],reports[3]]};
  assert.equal(lab.selectView(vc).requiredValue,a);
  assert.throws(()=>stores[3].prepare({round:1,value:b,viewCertificate:vc}));
  assert.throws(()=>stores[1].commit(p));
  assert.equal(lab.finalized({prepared:p,commit:c}).value,a);
  const next={scope:lab.scope,round:1,value:a,votes:stores.slice(1).map(s=>s.prepare({round:1,value:a,viewCertificate:vc}))};
  const nc={scope:lab.scope,round:1,value:a,votes:stores.slice(1).map(s=>s.commit(next))};
  assert.equal(lab.finalized({prepared:next,commit:nc}).value,a);
 }finally{close();}
});
