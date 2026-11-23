import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync,sign} from 'node:crypto';
import {mkdtemp,mkdir,writeFile,readFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {authorityRenewalTranscript,initialAuthorityChain,
 createSignedAuthorityRenewalLab} from '../standalone-relay/native-authority-renewal-lab.mjs';

const hash=b=>createHash('sha256').update(b).digest('hex');
const configPin='a'.repeat(64),initialStatePin='b'.repeat(64),initialPolicyPin='c'.repeat(64);
const authorityId='authority-lab-one';
const state=t=>({format:'quantic-relay-state',version:3,savedAt:new Date(t).toISOString(),manifests:[],cryptoProfiles:[]});
const policy=active=>[{address:'alice',active}];
async function fixture(t){
 const dir=await mkdtemp(join(tmpdir(),'quantic-authority-renew-'));
 await mkdir(join(dir,'renewals'),{mode:0o700});
 const signer=generateKeyPairSync('ed25519');
 const publicKey=signer.publicKey.export({type:'spki',format:'der'}).toString('base64url');
 const initialSnapshot={state:state(t),policy:policy(true)};
 const open=()=>createSignedAuthorityRenewalLab({
  directory:dir,authorityId,configPin,initialStatePin,initialPolicyPin,
  publicKey,initialSnapshot,now:()=>t
 });
 const root=initialAuthorityChain(authorityId,configPin,initialStatePin,initialPolicyPin);
 const put=async(n,previousHash,{clock=t,st=state(clock),pol=policy(true),wrongSig=false,corrupt=false}={})=>{
  const folder=join(dir,'renewals',String(n).padStart(6,'0'));
  await mkdir(folder,{mode:0o700});
  const sb=Buffer.from(JSON.stringify(st)),pb=Buffer.from(JSON.stringify(pol));
  const data={format:'quantic-native-authority-renewal/v1',authorityId,sequence:n,
   previousHash,stateHash:hash(sb),policyHash:hash(pb),savedAt:st.savedAt};
  const sig=sign(null,authorityRenewalTranscript(data),wrongSig?
   generateKeyPairSync('ed25519').privateKey:signer.privateKey).toString('base64url');
  await writeFile(join(folder,'state.json'),corrupt?Buffer.from('{}'):sb,{mode:0o600,flag:'wx'});
  await writeFile(join(folder,'policy.json'),pb,{mode:0o600,flag:'wx'});
  await writeFile(join(folder,'approval.json'),Buffer.from(JSON.stringify({...data,signature:sig})),{mode:0o600,flag:'wx'});
  return hash(authorityRenewalTranscript(data));
 };
 return{dir,open,root,put,close:()=>rm(dir,{recursive:true,force:true})};
}
test('separately signed renewal commits a monotonic durable head, survives a new controller and supports revocation',async()=>{
 const now=Date.now(),f=await fixture(now);
 try{
  const c=await f.open();
  assert.equal(c.status().sequence,0);
  assert.equal((await c.load()).policy[0].active,true);
  const approved=await f.put(1,f.root,{pol:policy(false)});
  const next=await c.load();
  assert.equal(next.policy[0].active,false);
  assert.equal(c.status().chainHash,approved);
  assert.equal(c.status().sequence,1);
  const head=JSON.parse(await readFile(join(f.dir,'accepted-head.json'),'utf8'));
  assert.equal(head.sequence,1);assert.equal(head.chainHash,approved);
  const again=await f.open();
  assert.equal(again.status().sequence,1);
  assert.equal((await again.load()).policy[0].active,false);
  const approved2=await f.put(2,approved,{pol:policy(true)});
  const resumed=await again.load();
  assert.equal(resumed.policy[0].active,true);
  assert.equal(again.status().sequence,2);
  assert.equal(again.status().chainHash,approved2);
 }finally{await f.close();}
});
test('forged Ed25519 renewal never advances durable head or state',async()=>{
 const f=await fixture(Date.now());
 try{
  const c=await f.open();await f.put(1,f.root,{wrongSig:true});
  await assert.rejects(c.load(),/renewal refused/);
  assert.equal(c.status().sequence,0);
  assert.equal(JSON.parse(await readFile(join(f.dir,'accepted-head.json'),'utf8')).sequence,0);
 }finally{await f.close();}
});
test('hash-consistent but unapproved or mutated snapshot refused with no rollback',async()=>{
 const f=await fixture(Date.now());
 try{
  const c=await f.open();await f.put(1,f.root,{corrupt:true});
  await assert.rejects(c.load(),/renewal refused/);
  assert.equal(c.status().sequence,0);
 }finally{await f.close();}
});
test('signed stale snapshot cannot refresh authority time; old timestamp never updated automatically',async()=>{
 const now=Date.now(),f=await fixture(now);
 try{
  const c=await f.open();
  await f.put(1,f.root,{clock:now-31000});
  await assert.rejects(c.load(),/renewal refused/);
  assert.equal((await readFile(join(f.dir,'accepted-head.json'),'utf8')).includes('"sequence":0'),true);
  assert.equal(c.status().sequence,0);
 }finally{await f.close();}
});
test('rollback or independent head tampering blocks further reads after accepted renewal',async()=>{
 const f=await fixture(Date.now());
 try{
  const c=await f.open(),approved=await f.put(1,f.root);
  await c.load();
  assert.equal(c.status().chainHash,approved);
  await writeFile(join(f.dir,'accepted-head.json'),Buffer.from(JSON.stringify({
   format:'quantic-native-authority-head/v1',sequence:0,chainHash:f.root
  })));
  await assert.rejects(c.load(),/renewal refused/);
 }finally{await f.close();}
});
test('operator cannot reset missing head when historical update directory remains',async()=>{
 const f=await fixture(Date.now());
 try{
  await f.put(1,f.root);
  await assert.rejects(f.open(),/renewal refused/);
 }finally{await f.close();}
});
test('concurrent HTTP-style loads serialize one approval and never skip a sequence',async()=>{
 const f=await fixture(Date.now());
 try{
  const c=await f.open();const h=await f.put(1,f.root);
  const snapshots=await Promise.all(Array.from({length:12},()=>c.load()));
  assert.equal(snapshots.length,12);
  assert.ok(snapshots.every(x=>x.state.format==='quantic-relay-state'));
  assert.equal(c.status().sequence,1);assert.equal(c.status().chainHash,h);
 }finally{await f.close();}
});
