import assert from 'node:assert/strict';
import test from 'node:test';
import {ProactiveLab} from '../labs/quantic-native/scattering/proactive-v08-network.mjs';
import {
 N,T,Q,LAB_GROUP,sha256,mod,scalarDecode,scalarEncode,groupEncode,
 createContribution,evalPoly,verifyShare,zeroConstantProof,encryptShare,decryptShare,
 newTransport,publicDer,lagrangeAtZero,validateRoundProof,signJson,newIdentity,
} from '../labs/quantic-native/scattering/proactive-v08-core.mjs';

async function withinLab(fn){const lab=await new ProactiveLab().start();try{return await fn(lab);}finally{await lab.close();}}

test('five-relay DKG and two proactive refresh epochs', {timeout:120000},async()=>withinLab(async lab=>{
  const init=await lab.round();assert.equal(init.packetCount,25);assert.deepEqual(init.cipherSizes,[768]);
  const one=await lab.recoverForAudit([1,3,5]);
  const fingerprints=[];
  for(let count=0;count<2;count++){
    const tick=await lab.round();assert.equal(tick.mode,'refresh');assert.equal(tick.packetCount,25);
    const after=await lab.recoverForAudit(count===0?[1,2,4]:[2,3,5]);
    assert.equal(after.secret,one.secret);
    assert.notDeepEqual(after.shares.map(x=>x.y),one.shares.map(x=>x.y));
    fingerprints.push(tick.commitmentFingerprint);
  }
  assert.notEqual(fingerprints[0],fingerprints[1]);
  assert.equal(new Set((await lab.states()).map(x=>x.epoch)).size,1);
}));

test('two compromised relay shares are not enough', {timeout:80000},async()=>withinLab(async lab=>{
  await lab.round();
  const audit=await lab.recoverForAudit();
  const secret=audit.secret;
  const partial=audit.shares.slice(0,2).map(v=>({x:v.x,y:scalarDecode(v.y)}));
  assert.throws(()=>lagrangeAtZero(partial),/three distinct/);
  const x1=BigInt(partial[0].x),x2=BigInt(partial[1].x);
  function inverse(n){let power=Q-2n,base=mod(n),out=1n;while(power){if(power&1n)out=out*base%Q;base=base*base%Q;power>>=1n;}return out;}
  const proposed=mod(secret+1n),
    delta1=mod(partial[0].y-proposed),delta2=mod(partial[1].y-proposed);
  const u1=mod(delta1*inverse(x1)),u2=mod(delta2*inverse(x2));
  const b=mod((u2-u1)*inverse(x2-x1)),a=mod(u1-b*x1);
  for(const point of partial)assert.equal(mod(proposed+a*BigInt(point.x)+b*BigInt(point.x)**2n),point.y);
  assert.notEqual(proposed,secret);
}));

test('ciphertext tampering aborts entire generation with no partial commit', {timeout:120000},async()=>withinLab(async lab=>{
  await lab.round();const before=await lab.states();
  await assert.rejects(lab.round({mutate(packets){
    const p=packets[0];p.envelope.ct=p.envelope.ct.slice(0,-4)+'AAAA';
  }}),/invalid signed packet|authenticate|decrypt|packet/);
  assert.deepEqual(await lab.states(),before);
  await lab.round();assert.equal((await lab.states())[0].epoch,2);
}));

test('old signed packet cannot be replayed in a new generation', {timeout:120000},async()=>withinLab(async lab=>{
  await lab.round();const original=structuredClone(lab.lastPackets[0]);const before=await lab.states();
  await assert.rejects(lab.round({mutate(packets){packets[0]=original;}}),/replayed\/duplicate\/invalid packet context/);
  assert.deepEqual(await lab.states(),before);
}));

test('missing dealer envelope fails closed', {timeout:120000},async()=>withinLab(async lab=>{
  await lab.round();const before=await lab.states();
  await assert.rejects(lab.round({mutate(packets){packets.pop();}}),/invalid round size/);
  assert.deepEqual(await lab.states(),before);
}));

test('unsigned commitment substitution fails closed', {timeout:120000},async()=>withinLab(async lab=>{
  await lab.round();const before=await lab.states();
  await assert.rejects(lab.round({mutate(packets,proofs){proofs[0].commitments[0]=groupEncode(1n);}}),/bad dealer proof signature/);
  assert.deepEqual(await lab.states(),before);
}));

test('signed non-zero refresh cannot impersonate zero-constant refresh',()=>{
  const id=newIdentity(),c=createContribution('dkg');
  const wrong={dealer:1,epoch:2,mode:'refresh',commitments:c.commitments,zeroBlind:scalarEncode(c.b[0])};
  const proof={...wrong,signature:signJson(wrong,id.privateKey)};
  assert.equal(zeroConstantProof(c.commitments,proof.zeroBlind),false);
  assert.throws(()=>validateRoundProof(proof,id.publicKey,2,'refresh'),/non-zero refresh constant/);
});

test('Pedersen commitments reject corrupt share and blinder',()=>{
  const c=createContribution('dkg');
  for(let x=1;x<=N;x++){
    const a=evalPoly(c.a,x),b=evalPoly(c.b,x);
    assert.equal(verifyShare(c.commitments,x,a,b),true);
    assert.equal(verifyShare(c.commitments,x,mod(a+1n),b),false);
    assert.equal(verifyShare(c.commitments,x,a,mod(b+1n)),false);
  }
  const refresh=createContribution('refresh');
  assert.equal(zeroConstantProof(refresh.commitments,refresh.zeroBlind),true);
});

test('AEAD rejects changed epoch and ciphertext',()=>{
  const r=newTransport();const ad={epoch:8,to:3,mode:'refresh'};
  const a=123456789n,b=987654321n;
  const envelope=encryptShare({a,b,ad,recipientPub:publicDer(r.publicKey)});
  assert.deepEqual(decryptShare({envelope,ad,receiverPriv:r.privateKey}),{a,b});
  assert.throws(()=>decryptShare({envelope,ad:{...ad,epoch:9},receiverPriv:r.privateKey}),/authenticate/);
  const altered={...envelope,ct:Buffer.from(Buffer.from(envelope.ct,'base64').map((v,i)=>i===0?v^1:v)).toString('base64')};
  assert.throws(()=>decryptShare({envelope:altered,ad,receiverPriv:r.privateKey}),/authenticate/);
});

test('security claims are restricted to isolated lab',()=>{
  assert.equal(N,5);assert.equal(T,3);
  assert.equal(LAB_GROUP.fieldBits,3071);
  assert.equal(LAB_GROUP.subgroupVerified,true);
  assert.equal(typeof sha256('public'),'string');
});
