import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,createHash,randomBytes} from 'node:crypto';
import {mkdtempSync,realpathSync,rmSync,readFileSync,writeFileSync} from 'node:fs';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {openQuorumFenceLab} from '../lib/quantic/pay-quorum-fence-lab.mjs';
const hash=x=>createHash('sha256').update(x).digest('hex');
function keys(){
 const cl=generateKeyPairSync('ed25519'),pq=generateKeyPairSync('ml-dsa-65');
 const a=cl.publicKey.export({type:'spki',format:'der'}),b=pq.publicKey.export({type:'spki',format:'der'});
 return {cl,pq,pub:{pin:hash(a),pqPin:hash(b),publicKey:a.toString('base64url'),pqPublicKey:b.toString('base64url')}};
}
const anchor=s=>({epoch:s.epoch,height:s.height,root:s.root,committee:s.committee,tip:s.tip});
test('3/4 challenge-bound independent witness freshness rejects rollback, stale signatures, equivocation and outages',{skip:process.platform!=='linux',timeout:60000},t=>{
 const root=realpathSync(mkdtempSync(join(tmpdir(),'quantic-freshness-'))),k=Array.from({length:4},keys),network='1'.repeat(64),initialCommittee='2'.repeat(64),genesisRoot='3'.repeat(64),cfg={network,shard:'demo-east',initialCommittee,genesisRoot,witnesses:k.map(x=>x.pub)},lab=openQuorumFenceLab(cfg),w=[];
 const value='4'.repeat(64);
 function open(i,createNew=false){const x=k[i];return lab.openWitness({directory:join(root,String(i)),createNew,credentials:{pin:x.pub.pin,classicalPrivateKey:x.cl.privateKey,pqPrivateKey:x.pq.privateKey},verifyDecision:r=>({value:r.value})});}
 try{
  for(let i=0;i<4;i++)w.push(open(i,true));
  const initial=anchor(w[0].status());
  const oldChallenge=randomBytes(32).toString('hex'),oldAttestations=w.map(x=>x.attestState(oldChallenge));
  assert.equal(lab.verifyFreshState(oldChallenge,oldAttestations,initial).witnesses,4);
  const disk=join(root,'0','fence.sqlite');w[0].close();const backup=readFileSync(disk);w[0]=open(0);
  const req={anchor:initial,mode:'vote',value},grants=w.slice(0,3).map(x=>x.grant(req));
  for(const x of w)x.complete(req,grants,{fixture:true});
  const latest=anchor(w[1].status());assert.equal(latest.height,1);assert.equal(latest.root,value);
  w[0].close();writeFileSync(disk,backup);w[0]=open(0);
  const challenge=randomBytes(32).toString('hex'),attest=w.map(x=>x.attestState(challenge));
  assert.equal(lab.verifyFreshState(challenge,attest,latest).witnesses,3);
  assert.throws(()=>lab.verifyFreshState(challenge,attest,initial),'restored witness must not establish a stale quorum');
  assert.throws(()=>lab.verifyFreshState(oldChallenge,attest,latest),'old challenge cannot authorize current observation');
  assert.throws(()=>lab.verifyFreshState(challenge,attest.slice(0,3),latest),'only two current witnesses');
  assert.throws(()=>lab.verifyFreshState(challenge,[attest[1],attest[1],attest[2],attest[0]],latest),'duplicate witness cannot create quorum');
  const forged=structuredClone(attest);forged[2].status.root='f'.repeat(64);
  assert.throws(()=>lab.verifyFreshState(challenge,forged,latest),'forgery must break quorum');
  const stale=structuredClone(attest);stale[0]=oldAttestations[0];
  assert.equal(lab.verifyFreshState(challenge,stale,latest).witnesses,3);
  const mismatched=structuredClone(attest);mismatched[1].signature=attest[2].signature;
  assert.throws(()=>lab.verifyFreshState(challenge,mismatched,latest));
  t.diagnostic('WITNESS_FRESHNESS_V1 '+JSON.stringify({nodes:4,quorum:3,rolledBackWitnesses:1,attestedHeight:1,outageTolerance:1,staleCertificateRefused:true,simulationOnly:true}));
 }finally{for(const x of w)try{x.close();}catch{}rmSync(root,{recursive:true,force:true});}
});
