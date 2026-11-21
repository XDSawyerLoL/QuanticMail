import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,createHash,randomBytes,sign} from 'node:crypto';
import {mkdtempSync,realpathSync,rmSync,cpSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createRoundCirculationLab} from '../lib/quantic/pay-circulation-lab.mjs';
import {createPayRoundLab} from '../lib/quantic/pay-round-lab.mjs';
import {openPayRoundReplica} from '../lib/quantic/pay-round-replica.mjs';
const sha=b=>createHash('sha256').update(b).digest('hex');
const spki=k=>k.publicKey.export({format:'der',type:'spki'});
const pair=type=>({cl:type==='ec'?generateKeyPairSync('ec',{namedCurve:'prime256v1'}):generateKeyPairSync(type),pq:generateKeyPairSync('ml-dsa-65')});
const pub=k=>({pin:sha(spki(k.cl)),publicKey:spki(k.cl).toString('base64url'),pqPin:sha(spki(k.pq)),pqPublicKey:spki(k.pq).toString('base64url')});
test('external checkpoint detects full replica rollback and same-height vote journal rollback',{skip:process.platform!=='linux'},()=>{
 const root=realpathSync(mkdtempSync(join(tmpdir(),'external-checkpoint-')));
 const wallets=[pair('ec'),pair('ec')],witnesses=Array.from({length:4},()=>pair('ed25519'));
 const config={admissionPolicy:'round-v3',wallets:wallets.map((w,i)=>({id:i?'demo-bob':'demo-alice',initialCents:i?0:10000,...pub(w)})),witnesses:witnesses.map(pub)};
 const lab=createRoundCirculationLab(config),now=1000000;
 const opts={directory:join(root,'node'),config,authorityPin:config.witnesses[0].pin,classicalPrivateKey:witnesses[0].cl.privateKey,pqPrivateKey:witnesses[0].pq.privateKey,clock:()=>now};
 let n;
 try{
  n=openPayRoundReplica({...opts,createNew:true});
  const initial=n.checkpoint();n.close();cpSync(opts.directory,join(root,'old'),{recursive:true});
  n=openPayRoundReplica({...opts,expectedCheckpoint:initial});
  const intent=lab.prepare([],{payer:'demo-alice',payee:'demo-bob',cents:7500,nonce:randomBytes(32).toString('hex'),now}),raw=lab.transcript(intent);
  const draft={admissionTime:now,proposals:[{intent,signature:sign('sha256',raw,{key:wallets[0].cl.privateKey,dsaEncoding:'ieee-p1363'}).toString('base64url'),pqSignature:sign(null,raw,wallets[0].pq.privateKey).toString('base64url')}]};
  const al=createPayRoundLab(lab.admissionRoundConfig([])),scope=al.scope,value=lab.draft([],draft).scope;
  n.admissionPrepare({scope,input:{draft,round:0}});
  const afterPrepare=n.checkpoint();n.close();
  const journal=join(opts.directory,'admission-height-1');cpSync(journal,join(root,'journal-old'),{recursive:true});
  n=openPayRoundReplica({...opts,expectedCheckpoint:afterPrepare});
  n.admissionChange({scope,input:1});
  const latest=n.checkpoint();assert.equal(latest.sequence,initial.sequence);assert.notEqual(latest.admission.root,afterPrepare.admission.root);n.close();
  rmSync(journal,{recursive:true,force:true});cpSync(join(root,'journal-old'),journal,{recursive:true});
  assert.throws(()=>openPayRoundReplica({...opts,expectedCheckpoint:latest}),/checkpoint mismatch/);
  rmSync(opts.directory,{recursive:true,force:true});cpSync(join(root,'old'),opts.directory,{recursive:true});
  assert.throws(()=>openPayRoundReplica({...opts,expectedCheckpoint:latest}),/checkpoint mismatch/);
  // Without an external checkpoint a locally consistent old snapshot still
  // opens. This explicitly demonstrates the remaining trust requirement.
  n=openPayRoundReplica(opts);assert.deepEqual(n.checkpoint(),initial);n.close();
 }finally{n?.close();rmSync(root,{recursive:true,force:true});}
});
