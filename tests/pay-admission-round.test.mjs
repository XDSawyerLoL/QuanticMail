import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,createHash,sign,randomBytes} from 'node:crypto';
import {mkdtempSync,realpathSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createRoundCirculationLab} from '../lib/quantic/pay-circulation-lab.mjs';
import {createPayRoundLab} from '../lib/quantic/pay-round-lab.mjs';
import {openAdmissionRound} from '../lib/quantic/pay-admission-round.mjs';
import {openRoundChain} from '../lib/quantic/pay-round-chain-store.mjs';
import {openPayRoundReplica} from '../lib/quantic/pay-round-replica.mjs';
const sha=b=>createHash('sha256').update(b).digest('hex');
const spki=k=>k.publicKey.export({type:'spki',format:'der'});
const pair=type=>({cl:type==='ec'?generateKeyPairSync('ec',{namedCurve:'prime256v1'}):generateKeyPairSync(type),pq:generateKeyPairSync('ml-dsa-65')});
const pub=k=>({pin:sha(spki(k.cl)),publicKey:spki(k.cl).toString('base64url'),pqPin:sha(spki(k.pq)),pqPublicKey:spki(k.pq).toString('base64url')});
for(const [size,locked] of [[4,false],[4,true],[7,false],[16,false],[16,true]])test(size+'-authority admission '+(locked?'preserves retained prepared locks':'recovers split')+' across restart before financial round',{skip:process.platform!=='linux'},()=>{
 const root=realpathSync(mkdtempSync(join(tmpdir(),'admission-round-'))),ids=['demo-alice','demo-bob','demo-shop'];
 const wallets=ids.map(()=>pair('ec')),witnesses=Array.from({length:size},()=>pair('ed25519'));
 const quorum=2*(size-1)/3+1;
 const config={admissionPolicy:size===4?'round-v2':'round-v3',wallets:ids.map((id,i)=>({id,initialCents:i===0?10000:0,...pub(wallets[i])})),witnesses:witnesses.map(pub)};
 let now=1000000,chain;const nodes=[],replicas=[];
 const opts=witnesses.map((w,i)=>({directory:join(root,'admission-'+i),config,records:[],authorityPin:config.witnesses[i].pin,classicalPrivateKey:w.cl.privateKey,pqPrivateKey:w.pq.privateKey,clock:()=>now}));
 const lab=createRoundCirculationLab(config),verifier=createPayRoundLab(lab.admissionRoundConfig([]));
 function proposal(payee){
  const intent=lab.prepare([],{payer:ids[0],payee,cents:7500,nonce:randomBytes(32).toString('hex'),now}),raw=lab.transcript(intent),k=wallets[0];
  return {intent,signature:sign('sha256',raw,{key:k.cl.privateKey,dsaEncoding:'ieee-p1363'}).toString('base64url'),pqSignature:sign(null,raw,k.pq.privateKey).toString('base64url')};
 }
 function restart(i){nodes[i].close();nodes[i]=openAdmissionRound(opts[i]);}
 try{
  chain=openRoundChain({directory:join(root,'chain'),config,createNew:true,clock:()=>now});
  const a={proposals:[proposal(ids[1])],admissionTime:now},b={proposals:[proposal(ids[2])],admissionTime:now};
  const av=lab.draft([],a).scope,bv=lab.draft([],b).scope,scope=verifier.scope;
  assert.notEqual(av,bv);assert.notEqual(scope,av);if(size===4)assert.notEqual(lab.snapshot([]).network,createRoundCirculationLab({...config,admissionPolicy:'quorum-v1'}).snapshot([]).network);else assert.throws(()=>createRoundCirculationLab({...config,admissionPolicy:'round-v2'}));
  assert.equal(verifier.committee.quorum,quorum);
  for(const o of opts)nodes.push(openAdmissionRound({...o,createNew:true}));
  const old=nodes.map((n,i)=>n.prepare({draft:i<(locked?quorum:quorum-1)?a:b,round:0}));
  if(locked){
   const qc={scope,round:0,value:av,votes:old.slice(0,quorum)};
   for(let i=0;i<quorum;i++)nodes[i].commit({draft:a,certificate:qc});
  }else assert.throws(()=>verifier.prepared({scope,round:0,value:av,votes:old.slice(0,quorum-1)}));
  for(let i=0;i<size;i++)restart(i);
  assert.throws(()=>nodes[0].prepare({draft:b,round:0}));
  const viewCertificate={scope,round:1,reports:nodes.map(n=>n.changeView(1)).slice(0,quorum)};
  assert.equal(verifier.selectView(viewCertificate).requiredValue,locked?av:null);
  if(locked)assert.throws(()=>nodes[0].prepare({draft:b,round:1,viewCertificate}));
  const draft=locked?a:b,value=locked?av:bv;
  const p={scope,round:1,value,votes:nodes.slice(0,quorum).map(n=>n.prepare({draft,round:1,viewCertificate}))};
  const c={scope,round:1,value,votes:nodes.slice(0,quorum).map(n=>n.commit({draft,certificate:p}))};
  const certificate={prepared:p,commit:c};
  assert.throws(()=>chain.admitExact({...draft,admissionCertificate:{prepared:p,commit:{...c,votes:c.votes.slice(0,quorum-1)}}}));
  assert.throws(()=>chain.admitExact({...locked?b:a,admissionCertificate:certificate}));
  const admission=nodes[0].learn({draft,certificate});
  assert.throws(()=>chain.admit(draft.proposals));
  const {info}=chain.admitExact(admission),fscope=info.scope,fvalue=info.candidates[0].value;
  for(let i=0;i<size;i++){
   const {records:ignored,...o}=opts[i];void ignored;
   replicas.push(openPayRoundReplica({...o,directory:join(root,'financial-'+i),createNew:true}));
   replicas[i].admit(admission);
  }
  const fp={scope:fscope,round:0,value:fvalue,votes:replicas.slice(0,quorum).map(n=>n.prepare({scope:fscope,input:{round:0,value:fvalue}}))};
  const fc={scope:fscope,round:0,value:fvalue,votes:replicas.slice(0,quorum).map(n=>n.commitVote({scope:fscope,input:fp}))};
  const record={admission,certificate:{prepared:fp,commit:fc}},receipt=chain.commit(record.certificate);
  for(const n of replicas){n.learn(record);assert.equal(n.status().root,receipt.root);}
  assert.equal(chain.snapshot().balances['demo-alice'],2500);assert.equal(chain.snapshot().totalCents,10000);
 }finally{chain?.close();for(const n of [...nodes,...replicas])n.close();rmSync(root,{recursive:true,force:true});}
});
