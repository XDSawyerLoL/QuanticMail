import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,realpathSync,rmSync,writeFileSync,readFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {openExternalVoteFence} from '../lib/quantic/pay-external-vote-fence-lab.mjs';
const h=n=>n.toString(16).padStart(64,'0');
const anchor=({epoch,height,root,committee,tip})=>({epoch,height,root,committee,tip});
test('independent fence persists mutually exclusive vote and handoff decisions across validator rollback',{skip:process.platform!=='linux'},t=>{
 const root=realpathSync(mkdtempSync(join(tmpdir(),'quantic-fence-'))),cfg={directory:join(root,'external'),network:h(1),shard:'demo-east',initialCommittee:h(2),genesisRoot:h(3)},handles=new Set();
 const open=(createNew=false)=>{const f=openExternalVoteFence({...cfg,createNew});handles.add(f);return f;};
 const close=f=>{f.close();handles.delete(f);};
 try{
  let a=open(true),b=open();const genesis=anchor(a.status());
  assert.throws(()=>a.lockHandoff(genesis,h(4)));
  assert.throws(()=>a.advanceBlock(genesis,h(5)));
  assert.equal(a.lockVote(genesis,h(5)),true);
  assert.equal(b.lockVote(genesis,h(5)),true);
  assert.throws(()=>b.lockVote(genesis,h(6)));
  close(a);a=open();assert.equal(a.status().pending,h(5));
  assert.throws(()=>a.advanceBlock(genesis,h(6)));
  a.advanceBlock(genesis,h(5));const first=anchor(b.status());
  assert.equal(first.height,1);assert.throws(()=>b.lockVote(genesis,h(5)));
  // Save a local validator snapshot while leaving the independently held
  // fence intact. Restoring the snapshot must not restore authorization.
  const snapshot=join(root,'validator.json');writeFileSync(snapshot,JSON.stringify(first));const backup=readFileSync(snapshot);
  a.lockHandoff(first,h(7));assert.throws(()=>b.lockVote(first,h(8)));
  assert.throws(()=>b.lockHandoff(first,h(9)));assert.throws(()=>b.activate(first,{transition:h(9),nextCommittee:h(10)}));
  close(a);a=open();assert.equal(a.status().mode,'handoff');assert.equal(a.status().pending,h(7));
  const next=a.activate(first,{transition:h(7),nextCommittee:h(10)});assert.deepEqual(anchor(b.status()),next);
  writeFileSync(snapshot,backup);const restored=JSON.parse(readFileSync(snapshot,'utf8'));
  assert.throws(()=>b.lockVote(restored,h(8)));assert.throws(()=>b.lockHandoff(restored,h(7)));
  assert.throws(()=>b.activate(restored,{transition:h(7),nextCommittee:h(10)}));
  b.lockVote(next,h(8));assert.throws(()=>a.lockHandoff(next,h(11)));assert.throws(()=>a.lockVote(next,h(12)));
  b.advanceBlock(next,h(8));assert.equal(a.status().height,2);assert.equal(a.status().epoch,1);
  assert.throws(()=>open(true));assert.throws(()=>openExternalVoteFence({...cfg,network:h(99)}));
  t.diagnostic('EXTERNAL_FENCE_V1 '+JSON.stringify({height:2,epoch:1,validatorRollbackRefused:true,externalRollbackNotCovered:true}));
 }finally{for(const f of handles)f.close();rmSync(root,{recursive:true,force:true});}
});
