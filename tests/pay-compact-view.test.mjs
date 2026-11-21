import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,createHash} from 'node:crypto';
import {createPayRoundLab} from '../lib/quantic/pay-round-lab.mjs';
import {compactPayView,expandPayView} from '../lib/quantic/pay-compact-view.mjs';
const sha=b=>createHash('sha256').update(b).digest('hex');
const spki=k=>k.export({type:'spki',format:'der'});
for(const size of [16,31])test(size+' member view deduplicates genuine hybrid proofs without relaxing verification',t=>{
 const keys=Array.from({length:size},()=>{
  const cl=generateKeyPairSync('ed25519'),pq=generateKeyPairSync('ml-dsa-65');
  const a=spki(cl.publicKey),b=spki(pq.publicKey),publicInfo={pin:sha(a),publicKey:a.toString('base64url'),pqPin:sha(b),pqPublicKey:b.toString('base64url')};
  return {publicInfo,credentials:{authorityPin:publicInfo.pin,classicalPrivateKey:cl.privateKey,pqPrivateKey:pq.privateKey}};
 });
 const config={network:'a'.repeat(64),height:1,previousRoot:'b'.repeat(64),authorities:keys.map(k=>k.publicInfo),committeeMode:true,admissionRound:true};
 const lab=createPayRoundLab(config),scope=lab.scope,quorum=lab.committee.quorum,value='c'.repeat(64),bad='d'.repeat(64);
 const nodes=keys.slice(0,quorum).map(k=>lab.openAuthority(k.credentials));
 const p={scope,round:0,value,votes:nodes.map(n=>n.prepare({round:0,value}))};
 // Equivalent prepared certificates can have different ordering.
 for(let i=0;i<quorum;i++)nodes[i].commit({...p,votes:i%2?[...p.votes].reverse():p.votes});
 const expanded={scope,round:1,reports:nodes.map(n=>n.changeView(1))},compact=compactPayView(expanded,size);
 const oldBytes=Buffer.byteLength(JSON.stringify(expanded)),newBytes=Buffer.byteLength(JSON.stringify(compact));
 t.diagnostic('expanded='+oldBytes+' compact='+newBytes+' ratio='+newBytes/oldBytes);
 assert.ok(newBytes<oldBytes/4);assert.ok(newBytes<524288);
 assert.equal(compact.votes.length,2*quorum);
 assert.equal(compact.proofs.length,2);
 assert.deepEqual(expandPayView(compact,size),expanded);
 assert.deepEqual(lab.selectView(compact),lab.selectView(expanded));
 const mutate=fn=>{const copy=structuredClone(compact);fn(copy);return copy;};
 for(const variant of [
  mutate(c=>{c.reports[0].prepared=999;}),
  mutate(c=>{c.reports.pop();}),
  mutate(c=>{c.proofs[0].votes[0]=c.proofs[0].votes[1];}),
  mutate(c=>{c.votes[0].pqSignature='A'.repeat(4412);}),
  mutate(c=>{c.reports[0].vote=c.reports[1].vote;}),
  mutate(c=>{c.proofs[0].value=bad;}),
  mutate(c=>{c.scope='e'.repeat(64);})
 ])assert.throws(()=>lab.selectView(variant));
 assert.throws(()=>nodes[0].prepare({round:1,value:bad,viewCertificate:compact}));
 const next={scope,round:1,value,votes:nodes.map(n=>n.prepare({round:1,value,viewCertificate:compact}))};
 const commit={scope,round:1,value,votes:nodes.map(n=>n.commit(next))};
 assert.equal(lab.finalized({prepared:next,commit}).value,value);
});
