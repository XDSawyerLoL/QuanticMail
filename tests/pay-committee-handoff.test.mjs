import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync,randomBytes,sign} from 'node:crypto';
import {openCommitteeHandoffLab} from '../lib/quantic/pay-committee-handoff-lab.mjs';
const sha=b=>createHash('sha256').update(b).digest('hex');
function key(){const cl=generateKeyPairSync('ed25519'),pq=generateKeyPairSync('ml-dsa-65'),a=cl.publicKey.export({format:'der',type:'spki'}),b=pq.publicKey.export({format:'der',type:'spki'});return {cl,pq,pub:{pin:sha(a),pqPin:sha(b),publicKey:a.toString('base64url'),pqPublicKey:b.toString('base64url')}};}
const roster=keys=>keys.map(k=>k.pub);
function votes(keys,msg){return keys.slice(0,11).map(k=>({pin:k.pub.pin,pqPin:k.pub.pqPin,signature:sign(null,msg,k.cl.privateKey).toString('base64url'),pqSignature:sign(null,msg,k.pq.privateKey).toString('base64url')})).sort((a,b)=>a.pin<b.pin?-1:1);}
const flip=s=>(s[0]==='A'?'B':'A')+s.slice(1);
test('three dual-certified committee handoffs, independent replay and rejected attacks',t=>{
 const keys=Array.from({length:4},()=>Array.from({length:16},key)),network=randomBytes(32).toString('hex'),shard='demo-east',cfg={network,shard,initialMembers:roster(keys[0])};
 const a=openCommitteeHandoffLab(cfg),b=openCommitteeHandoffLab(cfg),records=[],start=performance.now();
 for(let i=0;i<3;i++){
  const anchor={network,shard,height:10*(i+1),root:randomBytes(32).toString('hex')};
  const proposal=a.draft(anchor,roster(keys[i+1]));
  const outgoing=votes(keys[i],a.outgoingBytes(proposal,anchor)),incoming=votes(keys[i+1],a.incomingBytes(proposal,anchor,outgoing)),record={proposal,outgoing,incoming};
  const before=a.current();
  for(const phase of ['outgoing','incoming']){
   const short=structuredClone(record);short[phase].pop();assert.throws(()=>a.apply(short,anchor));
   const duplicate=structuredClone(record);duplicate[phase][1]=duplicate[phase][0];assert.throws(()=>a.apply(duplicate,anchor));
   for(const field of ['signature','pqSignature']){const bad=structuredClone(record);bad[phase][0][field]=flip(bad[phase][0][field]);assert.throws(()=>a.apply(bad,anchor));}
  }
  for(const field of ['root','previous','incoming']){const bad=structuredClone(record);bad.proposal[field]='f'.repeat(64);assert.throws(()=>a.apply(bad,anchor));}
  assert.throws(()=>a.apply(record,{...anchor,height:anchor.height+1}));
  assert.throws(()=>a.apply(record,{...anchor,shard:'demo-other'}));
  const wrong=structuredClone(record);wrong.incoming=votes(keys[i],a.incomingBytes(proposal,anchor,outgoing));assert.throws(()=>a.apply(wrong,anchor));
  assert.deepEqual(a.current(),before);
  const x=a.apply(record,anchor);assert.equal(x.activationHeight,anchor.height+1);assert.equal(x.epoch,i+1);assert.deepEqual(b.apply(record,anchor),x);assert.deepEqual(a.current(),b.current());
  assert.throws(()=>a.apply(record,anchor));records.push({record,anchor});
 }
 const replay=openCommitteeHandoffLab(cfg);for(const {record,anchor} of records)replay.apply(record,anchor);assert.deepEqual(replay.current(),a.current());
 assert.throws(()=>a.draft({network,shard,height:40,root:'a'.repeat(64)},roster(keys[3])));
 t.diagnostic('COMMITTEE_HANDOFF_V1 '+JSON.stringify({rotations:3,committees:4,keys:64,quorumEach:11,hybridVotesPerRotation:22,elapsedMs:performance.now()-start,simulationOnly:true}));
});
