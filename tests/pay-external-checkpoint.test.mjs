import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,createHash,randomBytes,sign} from 'node:crypto';
import {mkdtempSync,realpathSync,rmSync,cpSync,chmodSync,readdirSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createRoundCirculationLab} from '../lib/quantic/pay-circulation-lab.mjs';
import {createPayRoundLab} from '../lib/quantic/pay-round-lab.mjs';
import {openPayRoundReplica} from '../lib/quantic/pay-round-replica.mjs';
import {openAnchoredPayReplica} from '../lib/quantic/pay-anchored-replica.mjs';
import {assertExternalPayCheckpoint} from '../lib/quantic/pay-external-checkpoint.mjs';
const sha=b=>createHash('sha256').update(b).digest('hex');
const spki=k=>k.publicKey.export({format:'der',type:'spki'});
const pair=type=>({cl:type==='ec'?generateKeyPairSync('ec',{namedCurve:'prime256v1'}):generateKeyPairSync(type),pq:generateKeyPairSync('ml-dsa-65')});
const pub=k=>({pin:sha(spki(k.cl)),publicKey:spki(k.cl).toString('base64url'),pqPin:sha(spki(k.pq)),pqPublicKey:spki(k.pq).toString('base64url')});
// Preserve exact private fixture modes even on runners with permissive umask.
function restore(src,dst){
 cpSync(src,dst,{recursive:true});
 chmodSync(dst,0o700);
 for(const e of readdirSync(dst,{withFileTypes:true})){
  const p=join(dst,e.name);
  if(e.isDirectory())privateModes(p);else chmodSync(p,0o600);
 }
}
function privateModes(p){
 chmodSync(p,0o700);
 for(const e of readdirSync(p,{withFileTypes:true})){
  const q=join(p,e.name);if(e.isDirectory())privateModes(q);else chmodSync(q,0o600);
 }
}
test('external checkpoint detects full replica rollback and same-height vote journal rollback',{skip:process.platform!=='linux'},()=>{
 const root=realpathSync(mkdtempSync(join(tmpdir(),'external-checkpoint-')));
 const wallets=[pair('ec'),pair('ec')],witnesses=Array.from({length:4},()=>pair('ed25519'));
 const config={admissionPolicy:'round-v3',wallets:wallets.map((w,i)=>({id:i?'demo-bob':'demo-alice',initialCents:i?0:10000,...pub(w)})),witnesses:witnesses.map(pub)};
 const lab=createRoundCirculationLab(config),now=1000000;
 const opts={directory:join(root,'node'),config,authorityPin:config.witnesses[0].pin,classicalPrivateKey:witnesses[0].cl.privateKey,pqPrivateKey:witnesses[0].pq.privateKey,clock:()=>now};
 let n;
 try{
  n=openPayRoundReplica({...opts,createNew:true});
  const initial=n.checkpoint();n.close();restore(opts.directory,join(root,'old'));
  n=openPayRoundReplica({...opts,expectedCheckpoint:initial});
  const intent=lab.prepare([],{payer:'demo-alice',payee:'demo-bob',cents:7500,nonce:randomBytes(32).toString('hex'),now}),raw=lab.transcript(intent);
  const draft={admissionTime:now,proposals:[{intent,signature:sign('sha256',raw,{key:wallets[0].cl.privateKey,dsaEncoding:'ieee-p1363'}).toString('base64url'),pqSignature:sign(null,raw,wallets[0].pq.privateKey).toString('base64url')}]};
  const al=createPayRoundLab(lab.admissionRoundConfig([])),scope=al.scope,value=lab.draft([],draft).scope;
  n.admissionPrepare({scope,input:{draft,round:0}});
  const afterPrepare=n.checkpoint();n.close();
  const journal=join(opts.directory,'admission-height-1');restore(journal,join(root,'journal-old'));
  n=openPayRoundReplica({...opts,expectedCheckpoint:afterPrepare});
  n.admissionChange({scope,input:1});
  const latest=n.checkpoint();assert.equal(latest.sequence,initial.sequence);assert.notEqual(latest.admission.root,afterPrepare.admission.root);n.close();
  rmSync(journal,{recursive:true,force:true});restore(join(root,'journal-old'),journal);
  assert.throws(()=>openPayRoundReplica({...opts,expectedCheckpoint:latest}),/checkpoint mismatch/);
  rmSync(opts.directory,{recursive:true,force:true});restore(join(root,'old'),opts.directory);
  assert.throws(()=>openPayRoundReplica({...opts,expectedCheckpoint:latest}),/checkpoint mismatch/);
  // Without an external checkpoint a locally consistent old snapshot still
  // opens. This explicitly demonstrates the remaining trust requirement.
  n=openPayRoundReplica(opts);assert.deepEqual(n.checkpoint(),initial);n.close();
  let retained=structuredClone(initial),writes=0,refuse=false;
  const anchor={read:()=>structuredClone(retained),compareAndSwap:(before,after)=>{
   assertExternalPayCheckpoint(before,retained);
   writes++;
   if(refuse)return false;
   retained=structuredClone(after);return true;
  }};
  n=openAnchoredPayReplica({...opts,anchor});
  n.admissionPrepare({scope,input:{draft,round:0}});
  assert.equal(writes,1);assert.equal(retained.admission.count,1);
  refuse=true;
  assert.throws(()=>n.admissionChange({scope,input:1}),/halted/);
  assert.equal(n.anchorStatus().halted,true);
  assert.throws(()=>n.status());
  n.close();
  // Local commit happened, external CAS refused, so no output was released
  // and opening again against the old anchor must be refused.
  assert.throws(()=>openAnchoredPayReplica({...opts,anchor}),/checkpoint mismatch/);
 }finally{n?.close();rmSync(root,{recursive:true,force:true});}
});
