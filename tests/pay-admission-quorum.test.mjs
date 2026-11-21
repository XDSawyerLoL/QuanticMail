import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,createHash,sign,randomBytes} from 'node:crypto';
import {mkdtempSync,realpathSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {openPayRoundReplica} from '../lib/quantic/pay-round-replica.mjs';
import {openRoundChain} from '../lib/quantic/pay-round-chain-store.mjs';
import {createRoundCirculationLab} from '../lib/quantic/pay-circulation-lab.mjs';
const sha=b=>createHash('sha256').update(b).digest('hex');
const spki=k=>k.publicKey.export({type:'spki',format:'der'});
const pair=type=>({cl:type==='ec'?generateKeyPairSync('ec',{namedCurve:'prime256v1'}):generateKeyPairSync(type),pq:generateKeyPairSync('ml-dsa-65')});
const pub=k=>({pin:sha(spki(k.cl)),publicKey:spki(k.cl).toString('base64url'),pqPin:sha(spki(k.pq)),pqPublicKey:spki(k.pq).toString('base64url')});
test('admission quorum prevents two incompatible admitted sets at one height, including after restart',{skip:process.platform!=='linux'},()=>{
 const root=realpathSync(mkdtempSync(join(tmpdir(),'admission-quorum-'))),ids=['demo-alice','demo-bob','demo-shop'],wallets=ids.map(()=>pair('ec')),witnesses=Array.from({length:4},()=>pair('ed25519'));
 const config={admissionPolicy:'quorum-v1',wallets:ids.map((id,i)=>({id,initialCents:i===0?10000:0,...pub(wallets[i])})),witnesses:witnesses.map(pub)};
 let now=1000000,chain;const nodes=[],opts=witnesses.map((w,i)=>({directory:join(root,'node-'+i),config,authorityPin:config.witnesses[i].pin,classicalPrivateKey:w.cl.privateKey,pqPrivateKey:w.pq.privateKey,clock:()=>now}));
 function proposal(payee){
  const intent=chain.prepare({payer:ids[0],payee,cents:7500,nonce:randomBytes(32).toString('hex')}),raw=chain.transcript(intent),k=wallets[0];
  return {intent,signature:sign('sha256',raw,{key:k.cl.privateKey,dsaEncoding:'ieee-p1363'}).toString('base64url'),pqSignature:sign(null,raw,k.pq.privateKey).toString('base64url')};
 }
 try{
  chain=openRoundChain({directory:join(root,'chain'),config,createNew:true,clock:()=>now});
  assert.notEqual(chain.snapshot().network,createRoundCirculationLab({...config,admissionPolicy:null}).snapshot([]).network);
  for(const o of opts)nodes.push(openPayRoundReplica({...o,createNew:true}));
  const a={proposals:[proposal(ids[1])],admissionTime:now},b={proposals:[proposal(ids[2])],admissionTime:now};
  assert.throws(()=>chain.admit(a.proposals));assert.throws(()=>nodes[0].admit(a));
  const first=nodes[0].voteAdmission(a);nodes[0].close();nodes[0]=openPayRoundReplica(opts[0]);
  assert.deepEqual(nodes[0].voteAdmission(a),first);
  assert.throws(()=>nodes[0].voteAdmission(b));
  const endorsements=[first,nodes[1].voteAdmission(a),nodes[2].voteAdmission(a)],minority=nodes[3].voteAdmission(b);
  assert.throws(()=>chain.admitExact({...a,endorsements:[first,first,endorsements[1]]}));
  assert.throws(()=>chain.admitExact({...b,endorsements:[minority,endorsements[0],endorsements[1]]}));
  assert.throws(()=>chain.admitExact({...a,endorsements:endorsements.slice(0,2)}));
  const admission={...a,endorsements}, {info}=chain.admitExact(admission),scope=info.scope,value=info.candidates[0].value;
  for(const n of nodes)n.admit(admission);
  const p={scope,round:0,value,votes:nodes.slice(0,3).map(n=>n.prepare({scope,input:{round:0,value}}))};
  const commit={scope,round:0,value,votes:nodes.slice(0,3).map(n=>n.commitVote({scope,input:p}))};
  const record={admission,certificate:{prepared:p,commit}};
  const receipt=chain.commit(record.certificate);
  for(const n of nodes){n.learn(record);assert.equal(n.status().root,receipt.root);}
  assert.deepEqual(chain.snapshot().balances,{'demo-alice':2500,'demo-bob':7500,'demo-shop':0});
 }finally{chain?.close();for(const n of nodes)n.close();rmSync(root,{recursive:true,force:true});}
});
