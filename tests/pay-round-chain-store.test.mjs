import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,createHash,sign,randomBytes} from 'node:crypto';
import {mkdtempSync,realpathSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {openRoundChain} from '../lib/quantic/pay-round-chain-store.mjs';
import {openPersistentPayRound} from '../lib/quantic/pay-round-store.mjs';
import {createCirculationLab} from '../lib/quantic/pay-circulation-lab.mjs';
const sha=b=>createHash('sha256').update(b).digest('hex');
const spki=k=>k.publicKey.export({type:'spki',format:'der'});
const pair=type=>({cl:type==='ec'?generateKeyPairSync('ec',{namedCurve:'prime256v1'}):generateKeyPairSync(type),pq:generateKeyPairSync('ml-dsa-65')});
const pub=k=>({pin:sha(spki(k.cl)),publicKey:spki(k.cl).toString('base64url'),pqPin:sha(spki(k.pq)),pqPublicKey:spki(k.pq).toString('base64url')});
test('successive certified round-chain transfers, persistent admission, restart, old certificate retry and no overspend',{skip:process.platform!=='linux'},()=>{
 const root=realpathSync(mkdtempSync(join(tmpdir(),'round-chain-'))),ids=['demo-alice','demo-bob','demo-shop'];
 const wallets=ids.map(()=>pair('ec')),witnesses=Array.from({length:4},()=>pair('ed25519'));
 const config={wallets:ids.map((id,i)=>({id,initialCents:i===0?10000:0,...pub(wallets[i])})),witnesses:witnesses.map(pub)};
 let now=1000000,chain;const opts={directory:join(root,'chain'),config,clock:()=>now};
 function proposal(payer,payee,cents){
  const intent=chain.prepare({payer,payee,cents,nonce:randomBytes(32).toString('hex')}),k=wallets[ids.indexOf(payer)],raw=chain.transcript(intent);
  return {intent,signature:sign('sha256',raw,{key:k.cl.privateKey,dsaEncoding:'ieee-p1363'}).toString('base64url'),pqSignature:sign(null,raw,k.pq.privateKey).toString('base64url')};
 }
 function reopen(){chain.close();chain=openRoundChain(opts);}
 function settle(payer,payee,cents){
  const proof=proposal(payer,payee,cents),info=chain.admit([proof]),value=info.candidates[0].value;
  reopen();assert.equal(chain.admission().info.scope,info.scope);
  assert.deepEqual(chain.admit([proof]),info);assert.throws(()=>chain.prepare({payer,payee,cents,nonce:randomBytes(32).toString('hex')}));
  assert.throws(()=>chain.admit([{...proof,intent:{...proof.intent,cents:cents+1}}]));
  const nodes=[];
  try{
   for(let i=0;i<4;i++)nodes.push(openPersistentPayRound({directory:join(root,'height-'+proof.intent.sequence+'-w'+i),createNew:true,config:info.config,authorityPin:config.witnesses[i].pin,classicalPrivateKey:witnesses[i].cl.privateKey,pqPrivateKey:witnesses[i].pq.privateKey}));
   const p={scope:info.scope,round:0,value,votes:nodes.slice(0,3).map(n=>n.prepare({round:0,value}))};
   const c={scope:info.scope,round:0,value,votes:nodes.slice(0,3).map(n=>n.commit(p))};
   assert.throws(()=>chain.commit({prepared:p,commit:{...c,votes:c.votes.slice(0,2)}}));
   const certificate={prepared:p,commit:c},receipt=chain.commit(certificate);
   for(const n of nodes)n.learn(certificate);
   reopen();assert.deepEqual(chain.commit(certificate),receipt);
   return {certificate,receipt};
  }finally{for(const n of nodes)n.close();}
 }
 try{
  chain=openRoundChain({...opts,createNew:true});
  assert.notEqual(chain.snapshot().network,createCirculationLab(config).snapshot([]).network);
  const first=settle(ids[0],ids[1],7500);now+=1000;
  settle(ids[1],ids[2],7000);now+=1000;
  settle(ids[2],ids[0],6000);
  assert.deepEqual(chain.snapshot().balances,{'demo-alice':8500,'demo-bob':500,'demo-shop':1000});
  assert.equal(chain.snapshot().totalCents,10000);assert.equal(chain.snapshot().sequence,3);
  assert.equal(chain.receipts().length,3);assert.deepEqual(chain.commit(first.certificate),first.receipt);
  assert.throws(()=>proposal(ids[2],ids[0],1001));assert.equal(chain.snapshot().sequence,3);
  assert.equal(chain.snapshot().realPaymentAuthorized,false);
 }finally{chain?.close();rmSync(root,{recursive:true,force:true});}
});
