import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,createHash} from 'node:crypto';
import {payCommittee} from '../lib/quantic/pay-committee.mjs';
import {createPayRoundLab} from '../lib/quantic/pay-round-lab.mjs';
const sha=b=>createHash('sha256').update(b).digest('hex');
const spki=k=>k.export({type:'spki',format:'der'});
test('strict 3f+1 sizing and quorum intersection',()=>{
 for(const n of [4,7,10,13,16,19,22,25,28,31]){
  const c=payCommittee(n);assert.equal(c.quorum,n-c.faults);assert.equal(c.intersection,c.faults+1);
 }
 for(const n of [0,3,5,6,15,17,32,34,4.5,'16'])assert.throws(()=>payCommittee(n));
});
test('31 distinct hybrid authorities require 21 votes and reject reduced, duplicate or foreign membership certificates',()=>{
 const keys=Array.from({length:31},()=>{
  const cl=generateKeyPairSync('ed25519'),pq=generateKeyPairSync('ml-dsa-65');
  const a=spki(cl.publicKey),b=spki(pq.publicKey);
  const publicInfo={pin:sha(a),publicKey:a.toString('base64url'),pqPin:sha(b),pqPublicKey:b.toString('base64url')};
  return {publicInfo,credentials:{authorityPin:publicInfo.pin,classicalPrivateKey:cl.privateKey,pqPrivateKey:pq.privateKey}};
 });
 const config={network:'a'.repeat(64),height:1,previousRoot:'b'.repeat(64),authorities:keys.map(k=>k.publicInfo),committeeMode:true,admissionRound:true};
 const lab=createPayRoundLab(config),v='c'.repeat(64);
 const nodes=keys.map(k=>lab.openAuthority(k.credentials));
 const p={scope:lab.scope,round:0,value:v,votes:nodes.slice(0,21).map(n=>n.prepare({round:0,value:v}))};
 assert.throws(()=>lab.prepared({...p,votes:p.votes.slice(0,20)}));
 assert.throws(()=>lab.prepared({...p,votes:[...p.votes.slice(0,20),p.votes[0]]}));
 const c={scope:lab.scope,round:0,value:v,votes:nodes.slice(0,21).map(n=>n.commit(p))};
 assert.equal(lab.finalized({prepared:p,commit:c}).value,v);
 const smaller=createPayRoundLab({...config,authorities:config.authorities.slice(0,16)});
 assert.notEqual(smaller.scope,lab.scope);
 assert.throws(()=>smaller.finalized({prepared:p,commit:c}));
 assert.throws(()=>createPayRoundLab({...config,committeeMode:false}));
});
