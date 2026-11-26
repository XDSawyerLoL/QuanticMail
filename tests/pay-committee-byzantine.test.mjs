// Synthetic adversarial signatures confined to generated lab keys.
import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,createHash,randomBytes,sign} from 'node:crypto';
import {mkdtempSync,realpathSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createRoundCirculationLab} from '../lib/quantic/pay-circulation-lab.mjs';
import {createPayRoundLab} from '../lib/quantic/pay-round-lab.mjs';
import {openPayRoundReplica} from '../lib/quantic/pay-round-replica.mjs';
import {compactPayView} from '../lib/quantic/pay-compact-view.mjs';
import {collectCommitteeVotes} from '../lib/quantic/pay-committee-quorum.mjs';
const sha=b=>createHash('sha256').update(b).digest('hex');
const spki=k=>k.publicKey.export({format:'der',type:'spki'});
const pair=type=>({cl:type==='ec'?generateKeyPairSync('ec',{namedCurve:'prime256v1'}):generateKeyPairSync(type),pq:generateKeyPairSync('ml-dsa-65')});
const pub=k=>({pin:sha(spki(k.cl)),publicKey:spki(k.cl).toString('base64url'),pqPin:sha(spki(k.pq)),pqPublicKey:spki(k.pq).toString('base64url')});
const range=(a,b)=>Array.from({length:b-a},(_,i)=>i+a);
test('five Byzantine signers cannot fork admission or double-spend against eleven persistent honest authorities',{skip:process.platform!=='linux',timeout:120000},async t=>{
 const root=realpathSync(mkdtempSync(join(tmpdir(),'pay-byzantine-'))),nodes=[];
 const ids=['demo-alice','demo-bob','demo-shop'],wallets=ids.map(()=>pair('ec')),witnesses=range(0,16).map(()=>pair('ed25519'));
 const config={admissionPolicy:'round-v3',wallets:ids.map((id,i)=>({id,initialCents:i?0:10000,...pub(wallets[i])})),witnesses:witnesses.map(pub)};
 const lab=createRoundCirculationLab(config);let now=1000000;
 const opts=range(0,11).map(i=>({directory:join(root,'node-'+i),config,authorityPin:config.witnesses[i].pin,classicalPrivateKey:witnesses[i].cl.privateKey,pqPrivateKey:witnesses[i].pq.privateKey,clock:()=>now}));
 const bad=range(11,16),early=range(0,6),late=range(6,11),intersection=range(5,11);
 function malicious(i,scope,phase,round,value){
  assert.ok(bad.includes(i));
  const w=witnesses[i],{pin,pqPin}=config.witnesses[i];
  const raw=Buffer.from(JSON.stringify(['quantic-pay-round-vote/v1',scope,phase,round,value,pin,pqPin]));
  return {pin,pqPin,signature:sign(null,raw,w.cl.privateKey).toString('base64url'),pqSignature:sign(null,raw,w.pq.privateKey).toString('base64url')};
 }
 function proposal(payee){
  const intent=lab.prepare([],{payer:ids[0],payee,cents:7500,nonce:randomBytes(32).toString('hex'),now}),raw=lab.transcript(intent);
  return {intent,signature:sign('sha256',raw,{key:wallets[0].cl.privateKey,dsaEncoding:'ieee-p1363'}).toString('base64url'),pqSignature:sign(null,raw,wallets[0].pq.privateKey).toString('base64url')};
 }
 function restart(i){nodes[i].close();nodes[i]=openPayRoundReplica(opts[i]);}
 function certificate(scope,round,value,votes){return {scope,round,value,votes};}
 function view(scope,round,reports){
  // Byzantine reporters falsely claim no retained prepared proof.
  return compactPayView({scope,round,reports:[...reports,...bad.map(i=>({scope,round,prepared:null,vote:malicious(i,scope,'view-change',round,null)}))]},16);
 }
 try{
  for(const o of opts)nodes.push(openPayRoundReplica({...o,createNew:true}));
  const left=proposal(ids[1]),right=proposal(ids[2]);
  const a={proposals:[left,right],admissionTime:now},b={proposals:[right],admissionTime:now};
  const al=createPayRoundLab(lab.admissionRoundConfig([])),scope=al.scope,av=lab.draft([],a).scope,bv=lab.draft([],b).scope;
  assert.notEqual(av,bv);
  const ap=certificate(scope,0,av,[...early.map(i=>nodes[i].admissionPrepare({scope,input:{draft:a,round:0}})),...bad.map(i=>malicious(i,scope,'prepare',0,av))]);
  const rival=certificate(scope,0,bv,[...late.map(i=>nodes[i].admissionPrepare({scope,input:{draft:b,round:0}})),...bad.map(i=>malicious(i,scope,'prepare',0,bv))]);
  assert.equal(rival.votes.length,10);assert.throws(()=>al.prepared(rival));
  const ac=certificate(scope,0,av,[...early.map(i=>nodes[i].admissionCommit({scope,input:{draft:a,certificate:ap}})),...bad.map(i=>malicious(i,scope,'commit',0,av))]);
  // Final certificate exists but is withheld from all honest signers.
  const hidden={prepared:ap,commit:ac};assert.equal(al.finalized(hidden).value,av);
  for(let i=0;i<11;i++)restart(i);
  const vc=view(scope,1,intersection.map(i=>nodes[i].admissionChange({scope,input:1})));
  assert.equal(al.selectView(vc).requiredValue,av);
  for(const i of intersection)assert.throws(()=>nodes[i].admissionPrepare({scope,input:{draft:b,round:1,viewCertificate:vc}}));
  const av1=certificate(scope,1,av,[...intersection.map(i=>nodes[i].admissionPrepare({scope,input:{draft:a,round:1,viewCertificate:vc}})),...bad.map(i=>malicious(i,scope,'prepare',1,av))]);
  const ac1=certificate(scope,1,av,[...intersection.map(i=>nodes[i].admissionCommit({scope,input:{draft:a,certificate:av1}})),...bad.map(i=>malicious(i,scope,'commit',1,av))]);
  assert.equal(al.finalized({prepared:av1,commit:ac1}).value,av);
  const admission={...a,admissionCertificate:{prepared:av1,commit:ac1}};
  for(const n of nodes)n.admit(admission);
  const info=lab.admit([],admission),fl=createPayRoundLab(info.config),fs=fl.scope;
  const fa=info.candidates.find(c=>c.payee===ids[1]).value,fb=info.candidates.find(c=>c.payee===ids[2]).value;
  // Both spend 75 out of 100; only one may settle.
  const fp=certificate(fs,0,fa,[...early.map(i=>nodes[i].prepare({scope:fs,input:{round:0,value:fa}})),...bad.map(i=>malicious(i,fs,'prepare',0,fa))]);
  const rivalPay=certificate(fs,0,fb,[...late.map(i=>nodes[i].prepare({scope:fs,input:{round:0,value:fb}})),...bad.map(i=>malicious(i,fs,'prepare',0,fb))]);
  assert.throws(()=>fl.prepared(rivalPay));
  const fc=certificate(fs,0,fa,[...early.map(i=>nodes[i].commitVote({scope:fs,input:fp})),...bad.map(i=>malicious(i,fs,'commit',0,fa))]);
  const first={admission,certificate:{prepared:fp,commit:fc}};
  const receipt=lab.receipt([],first);
  for(let i=0;i<11;i++)restart(i);
  const fv=view(fs,1,intersection.map(i=>nodes[i].changeView({scope:fs,input:1})));
  assert.equal(fl.selectView(fv).requiredValue,fa);
  for(const i of intersection)assert.throws(()=>nodes[i].prepare({scope:fs,input:{round:1,value:fb,viewCertificate:fv}}));
  // Authentic but wrong phase/round/value signatures from five compromised
  // authorities must not be counted by the collector.
  const targets=range(0,16).map(i=>({authorityPin:config.witnesses[i].pin,client:i}));
  await assert.rejects(collectCommitteeVotes({lab:fl,authorities:targets,phase:'prepare',round:1,value:fb,invoke:async i=>{
   if(i<11)throw Error('honest authority refuses conflict');
   return malicious(i,fs,'prepare',1,fb);
  }}));
  // The honest quorum can still progress after the five stop helping.
  const honestReports=range(0,5).map(i=>nodes[i].changeView({scope:fs,input:1}));
  const reports=[...honestReports,...intersection.map(i=>nodes[i].changeView({scope:fs,input:1}))];
  const honestView=compactPayView({scope:fs,round:1,reports},16);
  assert.equal(fl.selectView(honestView).requiredValue,fa);
  const p=certificate(fs,1,fa,nodes.map(n=>n.prepare({scope:fs,input:{round:1,value:fa,viewCertificate:honestView}})));
  const c=certificate(fs,1,fa,nodes.map(n=>n.commitVote({scope:fs,input:p})));
  const final={admission,certificate:{prepared:p,commit:c}};
  const next=lab.receipt([],final);assert.equal(next.root,receipt.root);
  for(const n of nodes){n.learn(final);assert.deepEqual(n.status().balances,{'demo-alice':2500,'demo-bob':7500,'demo-shop':0});}
  assert.throws(()=>lab.receipt([final],first));
  t.diagnostic('Five genuine equivocating hybrid keys, hidden certificates and false view reports; 11 honest persistent ledgers settle one debit.');
 }finally{for(const n of nodes)n.close();rmSync(root,{recursive:true,force:true});}
});
