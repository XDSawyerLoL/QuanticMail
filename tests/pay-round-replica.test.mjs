import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,createHash,sign,randomBytes} from 'node:crypto';
import {mkdtempSync,realpathSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {openPayRoundReplica} from '../lib/quantic/pay-round-replica.mjs';
import {openRoundChain} from '../lib/quantic/pay-round-chain-store.mjs';
const sha=b=>createHash('sha256').update(b).digest('hex');
const spki=k=>k.publicKey.export({type:'spki',format:'der'});
const pair=type=>({cl:type==='ec'?generateKeyPairSync('ec',{namedCurve:'prime256v1'}):generateKeyPairSync(type),pq:generateKeyPairSync('ml-dsa-65')});
const pub=k=>({pin:sha(spki(k.cl)),publicKey:spki(k.cl).toString('base64url'),pqPin:sha(spki(k.pq)),pqPublicKey:spki(k.pq).toString('base64url')});
test('replicas roll forward from independent retained chains, catch up certified missed heights and never recreate missing vote journals',{skip:process.platform!=='linux'},()=>{
 const root=realpathSync(mkdtempSync(join(tmpdir(),'round-replicas-'))),ids=['demo-alice','demo-bob','demo-shop'];
 const wallets=ids.map(()=>pair('ec')),witnesses=Array.from({length:4},()=>pair('ed25519'));
 const config={wallets:ids.map((id,i)=>({id,initialCents:i===0?10000:0,...pub(wallets[i])})),witnesses:witnesses.map(pub)};
 let now=1000000,chain;const nodes=[];
 const opts=witnesses.map((w,i)=>({directory:join(root,'node-'+i),config,authorityPin:config.witnesses[i].pin,classicalPrivateKey:w.cl.privateKey,pqPrivateKey:w.pq.privateKey,clock:()=>now}));
 function proposal(payer,payee,cents){
  const intent=chain.prepare({payer,payee,cents,nonce:randomBytes(32).toString('hex')}),k=wallets[ids.indexOf(payer)],raw=chain.transcript(intent);
  return {intent,signature:sign('sha256',raw,{key:k.cl.privateKey,dsaEncoding:'ieee-p1363'}).toString('base64url'),pqSignature:sign(null,raw,k.pq.privateKey).toString('base64url')};
 }
 function restart(i){nodes[i].close();nodes[i]=openPayRoundReplica(opts[i]);}
 function settle(from,to,cents,active){
  const info=chain.admit([proposal(from,to,cents)]),{admission}=chain.admission(),scope=info.scope,value=info.candidates[0].value;
  for(const i of active){assert.equal(nodes[i].admit(admission).scope,scope);restart(i);}
  assert.throws(()=>nodes[active[0]].admit({...admission,admissionTime:admission.admissionTime+1}));
  const p={scope,round:0,value,votes:active.map(i=>nodes[i].prepare({scope,input:{round:0,value}}))};
  const commit={scope,round:0,value,votes:active.map(i=>nodes[i].commitVote({scope,input:p}))};
  const record={admission,certificate:{prepared:p,commit}};
  const receipt=chain.commit(record.certificate);
  for(const i of active){assert.deepEqual(nodes[i].learn(record),receipt);restart(i);assert.equal(nodes[i].status().root,receipt.root);}
  return record;
 }
 try{
  chain=openRoundChain({directory:join(root,'coordinator'),config,clock:()=>now,createNew:true});
  for(const o of opts)nodes.push(openPayRoundReplica({...o,createNew:true}));
  const first=settle(ids[0],ids[1],7500,[0,1,2]);
  assert.equal(nodes[3].status().sequence,0);
  now+=1000;const second=settle(ids[1],ids[2],7000,[0,1,2]);
  assert.throws(()=>nodes[3].learn(second));
  assert.throws(()=>nodes[3].learn({...first,certificate:{...first.certificate,commit:{...first.certificate.commit,votes:first.certificate.commit.votes.slice(0,2)}}}));
  now+=130000;nodes[3].learn(nodes[0].record(1));nodes[3].learn(nodes[0].record(2));restart(3);
  assert.equal(nodes[3].status().root,chain.snapshot().root);
  const third=settle(ids[2],ids[0],6000,[0,1,3]);nodes[2].learn(third);
  for(const n of nodes){assert.deepEqual(n.status().balances,{'demo-alice':8500,'demo-bob':500,'demo-shop':1000});assert.equal(n.status().sequence,3);}
  const info=chain.admit([proposal(ids[0],ids[2],100)]),{admission}=chain.admission();
  nodes[0].admit(admission);nodes[0].prepare({scope:info.scope,input:{round:0,value:info.candidates[0].value}});
  nodes[0].close();rmSync(join(opts[0].directory,'height-4'),{recursive:true,force:true});
  assert.throws(()=>openPayRoundReplica(opts[0]));
 }finally{chain?.close();for(const n of nodes)n.close();rmSync(root,{recursive:true,force:true});}
});
