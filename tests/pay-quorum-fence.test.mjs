import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,createHash,sign,verify} from 'node:crypto';
import {mkdtempSync,realpathSync,rmSync,readFileSync,writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {openQuorumFenceLab} from '../lib/quantic/pay-quorum-fence-lab.mjs';
const h=n=>n.toString(16).padStart(64,'0');
const sha=b=>createHash('sha256').update(b).digest('hex');
const anchor=({epoch,height,root,committee,tip})=>({epoch,height,root,committee,tip});
function key(){const cl=generateKeyPairSync('ed25519'),pq=generateKeyPairSync('ml-dsa-65'),a=cl.publicKey.export({format:'der',type:'spki'}),b=pq.publicKey.export({format:'der',type:'spki'});return {cl,pq,pub:{pin:sha(a),pqPin:sha(b),publicKey:a.toString('base64url'),pqPublicKey:b.toString('base64url')}};}
test('three of four durable hybrid witnesses reject conflicting locks after one real database rollback',{skip:process.platform!=='linux'},t=>{
 const root=realpathSync(mkdtempSync(join(tmpdir(),'quantic-quorum-'))),keys=Array.from({length:4},key),decisionKeys=Array.from({length:16},key),cfg={network:h(1),shard:'demo-east',initialCommittee:h(2),genesisRoot:h(3),witnesses:keys.map(k=>k.pub)};
 // Independent synthetic 11-of-16 dual-signature decision oracle. Not the
 // actual Pay ledger certificate adapter. Tests that permits alone cannot
 // advance the witness and that real signatures are required by the oracle.
 const message=(r,next)=>Buffer.from(JSON.stringify(['fixture-finality/v1',cfg.network,cfg.shard,r.anchor,r.mode,r.value,next]));
 function proof(r,next=null){const b=message(r,next);return {next,votes:decisionKeys.slice(0,11).map((k,i)=>({i,cl:sign(null,b,k.cl.privateKey).toString('base64url'),pq:sign(null,b,k.pq.privateKey).toString('base64url')}))};}
 function verifyDecision(r,p){assert.ok(Array.isArray(p?.votes)&&p.votes.length===11);const used=new Set(),b=message(r,p.next);for(const v of p.votes){const k=decisionKeys[v.i];assert.ok(k&&!used.has(v.i));used.add(v.i);assert.ok(verify(null,b,k.cl.publicKey,Buffer.from(v.cl,'base64url'))&&verify(null,b,k.pq.publicKey,Buffer.from(v.pq,'base64url')));}return r.mode==='vote'?{value:r.value}:{transition:r.value,nextCommittee:p.next};}
 const lab=openQuorumFenceLab(cfg),w=[];
 function open(i,createNew=false){const k=keys[i];return lab.openWitness({directory:join(root,String(i)),credentials:{pin:k.pub.pin,classicalPrivateKey:k.cl.privateKey,pqPrivateKey:k.pq.privateKey},createNew,verifyDecision});}
 try{
  for(let i=0;i<4;i++)w.push(open(i,true));const a=anchor(w[0].status());
  const path=join(root,'0','fence.sqlite');w[0].close();const backup=readFileSync(path);w[0]=open(0);
  const r={anchor:a,mode:'vote',value:h(4)},conflict={...r,value:h(5)};
  const grants=w.slice(0,3).map(x=>x.grant(r));assert.equal(lab.verifyGrants(r,grants).votes,3);
  assert.throws(()=>lab.verifyGrants(r,grants.slice(0,2)));assert.throws(()=>lab.verifyGrants(r,[grants[0],grants[0],grants[2]]));assert.throws(()=>lab.verifyGrants(conflict,grants));
  const forged=structuredClone(grants);forged[0].pqSignature='A'.repeat(4412);assert.throws(()=>lab.verifyGrants(r,forged));
  assert.throws(()=>w[0].complete(r,grants,null));assert.equal(w[0].status().height,0);
  w[0].close();writeFileSync(path,backup);w[0]=open(0);
  const alternate=[w[0].grant(conflict),w[3].grant(conflict)];assert.throws(()=>w[1].grant(conflict));assert.throws(()=>w[2].grant(conflict));assert.throws(()=>lab.verifyGrants(conflict,alternate));
  // Recover original certified outcome on the two intact supporters. The
  // inconsistent witnesses fail closed; no claim of recovery/liveness.
  const final=proof(r);for(const i of [1,2])w[i].complete(r,grants,final);
  assert.equal(w[1].status().height,1);assert.throws(()=>w[0].complete(r,grants,final));assert.throws(()=>w[1].grant(r));
  // Use a separate fresh four-witness fixture for successful rotation.
  const clean=keys.map((k,i)=>lab.openWitness({directory:join(root,'clean-'+i),credentials:{pin:k.pub.pin,classicalPrivateKey:k.cl.privateKey,pqPrivateKey:k.pq.privateKey},createNew:true,verifyDecision}));
  try{const g=clean.slice(0,3).map(x=>x.grant(r));for(const x of clean)x.complete(r,g,final);const before=anchor(clean[0].status()),handoff={anchor:before,mode:'handoff',value:h(6)},hg=clean.slice(0,3).map(x=>x.grant(handoff));assert.throws(()=>clean[1].grant({anchor:before,mode:'vote',value:h(7)}));for(const x of clean)x.complete(handoff,hg,proof(handoff,h(8)));for(const x of clean){assert.equal(x.status().epoch,1);assert.throws(()=>x.grant(handoff));}const next={anchor:anchor(clean[0].status()),mode:'vote',value:h(9)},ng=clean.slice(1).map(x=>x.grant(next));for(const x of clean)x.complete(next,ng,proof(next));assert.equal(clean[0].status().height,2);}finally{for(const x of clean)x.close();}
  t.diagnostic('QUORUM_FENCE_V1 '+JSON.stringify({witnesses:4,quorum:3,rolledBack:1,conflictingGrants:2,conflictingQuorum:false,rotation:true,simulationOnly:true}));
 }finally{for(const x of w)x.close();rmSync(root,{recursive:true,force:true});}
});
