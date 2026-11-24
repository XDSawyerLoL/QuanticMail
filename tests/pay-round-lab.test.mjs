import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,createHash} from 'node:crypto';
import {createPayRoundLab} from '../lib/quantic/pay-round-lab.mjs';
const sha=b=>createHash('sha256').update(b).digest('hex');
const spki=k=>k.publicKey.export({type:'spki',format:'der'});
function fixture(){
 const keys=Array.from({length:4},()=>({cl:generateKeyPairSync('ed25519'),pq:generateKeyPairSync('ml-dsa-65')}));
 const authorities=keys.map(k=>({pin:sha(spki(k.cl)),publicKey:spki(k.cl).toString('base64url'),pqPin:sha(spki(k.pq)),pqPublicKey:spki(k.pq).toString('base64url')}));
 const lab=createPayRoundLab({network:'a'.repeat(64),height:1,previousRoot:'b'.repeat(64),authorities});
 const nodes=keys.map((k,i)=>lab.openAuthority({authorityPin:authorities[i].pin,classicalPrivateKey:k.cl.privateKey,pqPrivateKey:k.pq.privateKey}));
 const qc=(round,value,votes)=>({scope:lab.scope,round,value,votes});
 const view=(round,reports)=>({scope:lab.scope,round,reports});
 return {lab,nodes,qc,view};
}
test('round change: 2-2 prepare split without commit certificate can progress with three signed reports',()=>{
 const {lab,nodes,qc,view}=fixture(),a='demo-alpha',b='demo-beta';
 const old=nodes.map((n,i)=>n.prepare({round:0,value:i<2?a:b}));
 assert.throws(()=>lab.prepared(qc(0,a,old.slice(0,2))));
 assert.throws(()=>nodes[0].prepare({round:0,value:b}));
 const reports=nodes.map(n=>n.changeView(1)),v=view(1,reports.slice(0,3));
 assert.equal(lab.selectView(v).requiredValue,null);
 assert.throws(()=>lab.selectView(view(1,[reports[0],reports[1]])));
 assert.throws(()=>lab.selectView(view(1,[reports[0],reports[0],reports[1]])));
 assert.throws(()=>nodes[0].prepare({round:0,value:a}));
 const p=qc(1,b,nodes.slice(0,3).map(n=>n.prepare({round:1,value:b,viewCertificate:v})));
 assert.throws(()=>nodes[0].prepare({round:1,value:a,viewCertificate:v}));
 const commit=qc(1,b,nodes.slice(0,3).map(n=>n.commit(p)));
 const c={prepared:p,commit};
 assert.throws(()=>lab.finalized({prepared:p,commit:{...commit,votes:commit.votes.slice(0,2)}}));
 assert.throws(()=>lab.finalized({prepared:p,commit:{...commit,votes:commit.votes.map(s=>({...s,pqSignature:undefined}))}}));
 assert.equal(lab.finalized(c).value,b);
 for(const n of nodes){n.learn(c);assert.throws(()=>n.changeView(2));}
});
test('round change carries a previously prepared certificate and refuses conflicting value or old-round commit',()=>{
 const {lab,nodes,qc,view}=fixture(),a='demo-alpha',b='demo-beta';
 const p=qc(0,a,nodes.slice(0,3).map(n=>n.prepare({round:0,value:a})));
 // Commit votes emitted but certificate withheld from the other nodes.
 const oldCommit=qc(0,a,nodes.slice(0,3).map(n=>n.commit(p)));
 const reports=nodes.map(n=>n.changeView(1));
 const v=view(1,[reports[1],reports[2],reports[3]]);
 assert.equal(lab.selectView(v).requiredValue,a);
 assert.throws(()=>nodes[3].prepare({round:1,value:b,viewCertificate:v}));
 assert.throws(()=>nodes[1].commit(p));
 assert.throws(()=>lab.selectView(view(1,[{...reports[1],prepared:null},reports[2],reports[3]])));
 const next=qc(1,a,nodes.slice(1).map(n=>n.prepare({round:1,value:a,viewCertificate:v})));
 const nextCommit=qc(1,a,nodes.slice(1).map(n=>n.commit(next)));
 assert.equal(lab.finalized({prepared:p,commit:oldCommit}).value,a);
 assert.equal(lab.finalized({prepared:next,commit:nextCommit}).value,a);
});
