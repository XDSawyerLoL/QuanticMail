import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,createHash,sign,randomBytes} from 'node:crypto';
import {performance} from 'node:perf_hooks';
import {encodePayBatchBinary,decodePayBatchBinary} from '../lib/quantic/pay-batch-binary-lab.mjs';
import {openPayReferenceLab} from '../lib/quantic/pay-reference-lab.mjs';
import {openPayBatchLab} from '../lib/quantic/pay-batch-lab.mjs';
import {createRoundCirculationLab} from '../lib/quantic/pay-circulation-lab.mjs';
const sha=b=>createHash('sha256').update(b).digest('hex');
function pair(type){
 const cl=type==='ec'?generateKeyPairSync('ec',{namedCurve:'prime256v1'}):generateKeyPairSync(type),pq=generateKeyPairSync('ml-dsa-65');
 const a=cl.publicKey.export({type:'spki',format:'der'}),b=pq.publicKey.export({type:'spki',format:'der'});
 return {cl,pq,pub:{pin:sha(a),publicKey:a.toString('base64url'),pqPin:sha(b),pqPublicKey:b.toString('base64url')}};
}
const now=1000000;
test('1000 individually hybrid-signed synthetic operations, one 11/16 prepare and commit certificate',t=>{
 const a=pair('ec'),b=pair('ec'),c=pair('ec'),keys=Array.from({length:16},()=>pair('ed25519'));
 const config={admissionPolicy:'round-v3',wallets:[{id:'demo-alice',initialCents:10000,...a.pub},{id:'demo-bob',initialCents:0,...b.pub},{id:'demo-shop',initialCents:0,...c.pub}],witnesses:keys.map(k=>k.pub)};
 const chain=createRoundCirculationLab(config),lab=openPayBatchLab({config});
 function tx(cents,payee='demo-bob'){
  const intent=chain.prepare([],{payer:'demo-alice',payee,cents,nonce:randomBytes(32).toString('hex'),now}),raw=chain.transcript(intent);
  return {intent,signature:sign('sha256',raw,{key:a.cl.privateKey,dsaEncoding:'ieee-p1363'}).toString('base64url'),pqSignature:sign(null,raw,a.pq.privateKey).toString('base64url')};
 }
 const start=performance.now(),proofs=Array.from({length:1000},(_,i)=>tx(1,i%2?'demo-bob':'demo-shop')),signed=performance.now();
 const proposal=lab.propose(proofs,now),projected=performance.now();
 const batch={proofs,time:now,value:proposal.value};
 const compact=encodePayBatchBinary(batch),decoded=decodePayBatchBinary(compact);
 assert.deepEqual(decoded,batch);
 assert.equal(lab.propose(decoded.proofs,decoded.time).value,proposal.value);
 assert.ok(compact.length<Buffer.byteLength(JSON.stringify(batch))*.7);
 assert.throws(()=>decodePayBatchBinary(compact.subarray(0,-1)));
 assert.throws(()=>decodePayBatchBinary(Buffer.concat([compact,Buffer.alloc(1)])));
 const tampered=Buffer.from(compact);tampered[tampered.length-10]^=1;
 assert.throws(()=>lab.propose(decodePayBatchBinary(tampered).proofs,now));
 t.diagnostic('BATCH_BINARY_V1 '+JSON.stringify({operations:proofs.length,jsonBytes:Buffer.byteLength(JSON.stringify(batch)),binaryBytes:compact.length}));
 // Two independently initialized caches. No signature or balance check is skipped.
 const sender=openPayReferenceLab({config}),receiver=openPayReferenceLab({config});
 try{
  const manifest=sender.publish(batch),all=receiver.missing(manifest);
  assert.equal(manifest.length,48078);assert.equal(all.length,1000);
  assert.throws(()=>receiver.resolve(manifest));
  const first=sender.exportProof(manifest,all[0]),corrupt=Buffer.from(first);corrupt[corrupt.length-1]^=1;
  assert.throws(()=>receiver.recover(manifest,all[0],corrupt));
  assert.equal(receiver.stats().entries,0);
  let recoveryBytes=0;const samples=[];
  for(let i=0;i<all.length;i++){
   const b=sender.exportProof(manifest,all[i]);receiver.recover(manifest,all[i],b);recoveryBytes+=b.length;
   if([499,899,989,999].includes(i))samples.push({cached:i+1,missing:receiver.missing(manifest).length,recoveryBytes});
  }
  assert.equal(receiver.missing(manifest).length,0);
  assert.deepEqual(receiver.resolve(manifest).balances,proposal.balances);
  assert.equal(receiver.resolve(manifest).value,proposal.value);
  assert.equal(receiver.stats().entries,1000);
  const altered=Buffer.from(manifest);altered[44]^=1;
  assert.throws(()=>receiver.resolve(altered));
  const wrongScope=Buffer.from(manifest);wrongScope[4]^=1;
  assert.throws(()=>receiver.missing(wrongScope));
  assert.throws(()=>receiver.missing(manifest.subarray(0,-1)));
  const duplicate=Buffer.from(manifest);duplicate.copyWithin(126,78,126);
  assert.throws(()=>receiver.missing(duplicate));
  assert.throws(()=>sender.publish({...batch,proofs:[proofs[0],proofs[0]]}));
  const total=receiver.stats().bytes;
  receiver.recover(manifest,all[0],first);assert.equal(receiver.stats().bytes,total);
  t.diagnostic('BATCH_REFERENCE_V1 '+JSON.stringify({operations:1000,fullBinaryBytes:compact.length,manifestBytes:manifest.length,coldRecoveryBytes:recoveryBytes,samples,fullCacheReduction:1-manifest.length/compact.length}));
  receiver.clear();assert.equal(receiver.stats().bytes,0);assert.throws(()=>receiver.resolve(manifest));
 }finally{sender.clear();receiver.clear();}
 assert.deepEqual(proposal.balances,{'demo-alice':9000,'demo-bob':500,'demo-shop':500});
 assert.equal(lab.propose([...proofs].reverse(),now).value,proposal.value);
 const nodes=keys.slice(0,11).map(k=>openPayBatchLab({config}).openAuthority({authorityPin:k.pub.pin,classicalPrivateKey:k.cl.privateKey,pqPrivateKey:k.pq.privateKey}));
 const voteStart=performance.now();
 const prepared={scope:lab.scope,round:0,value:proposal.value,votes:nodes.map(n=>n.prepare({proofs,time:now,value:proposal.value}))};
 assert.throws(()=>nodes[0].commit({...prepared,votes:prepared.votes.slice(0,10)}));
 const commit={scope:lab.scope,round:0,value:proposal.value,votes:nodes.map(n=>n.commit(prepared))},certificate={prepared,commit};
 const certified=performance.now(),receipt=proposal.receipt(999,certificate);
 assert.equal(lab.verifyReceipt(receipt).included,true);assert.equal(receipt.siblings.length,10);
 for(const n of nodes)n.learn(certificate);
 const changed=fn=>{const r=structuredClone(receipt);fn(r);return r;};
 for(const r of [changed(r=>r.proof.intent.cents++),changed(r=>r.siblings[0]='a'.repeat(64)),changed(r=>r.header.count--),changed(r=>r.header.stateRoot='f'.repeat(64)),changed(r=>r.certificate.commit.votes.pop()),changed(r=>r.certificate.prepared.votes[0].pqSignature='A'.repeat(4412)),changed(r=>r.index=0)])assert.throws(()=>lab.verifyReceipt(r));
 assert.throws(()=>lab.propose([proofs[0],proofs[0]],now));
 assert.throws(()=>lab.propose([tx(6000),tx(6000)],now));
 assert.throws(()=>lab.propose([proofs[0]],now+120000));
 assert.throws(()=>lab.propose([proofs[0]].map(p=>({...p,pqSignature:'A'.repeat(4412)})),now));
 const alt=lab.propose([tx(1)],now);assert.throws(()=>nodes[0].prepare({proofs:[proofs[0]],time:now,value:alt.value}));
 const odd=proofs.slice(0,3),p3=lab.propose(odd,now);
 // Fresh isolated test instance, not a second decision allowed on the same live ledger.
 const lab3=openPayBatchLab({config}),n3=keys.slice(0,11).map(k=>lab3.openAuthority({authorityPin:k.pub.pin,classicalPrivateKey:k.cl.privateKey,pqPrivateKey:k.pq.privateKey}));
 const q3={scope:lab3.scope,round:0,value:p3.value,votes:n3.map(n=>n.prepare({proofs:odd,time:now,value:p3.value}))};
 const c3={prepared:q3,commit:{scope:lab3.scope,round:0,value:p3.value,votes:n3.map(n=>n.commit(q3))}};
 assert.equal(lab3.verifyReceipt(p3.receipt(2,c3)).included,true);
 const bytes=v=>Buffer.byteLength(JSON.stringify(v)),certBytes=bytes(certificate);
 t.diagnostic('BATCH_LAB_V1 '+JSON.stringify({operations:proofs.length,quorum:11,clientSigningMs:signed-start,coordinatorValidationMs:projected-signed,serialAuthorityValidationAndVotingMs:certified-voteStart,clientProofBytes:bytes(proofs),certificateBytes:certBytes,certificateBytesAmortized:certBytes/proofs.length,individualReceiptBytes:bytes(receipt),merkleSiblings:receipt.siblings.length,simulationOnly:true}));
});
