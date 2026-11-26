import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,createHash,sign,randomBytes} from 'node:crypto';
import {mkdtempSync,realpathSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {openMultiwalletLab} from '../lib/quantic/pay-multiwallet-lab.mjs';
import {newPayCheckpointRequest,attestPayCheckpoint} from '../lib/quantic/pay-lab-checkpoint.mjs';
const sha=b=>createHash('sha256').update(b).digest('hex');
const spki=k=>k.publicKey.export({format:'der',type:'spki'});
test('multi-wallet settlement conserves value, binds payer, refuses replay under another wallet, retains exact receipt after restart',{skip:process.platform!=='linux'},()=>{
 const root=realpathSync(mkdtempSync(join(tmpdir(),'pay-multi-'))),now=1000000;
 const witnesses=Array.from({length:4},()=>({ec:generateKeyPairSync('ed25519'),pq:generateKeyPairSync('ml-dsa-65')}));
 const trustedAuthorities=witnesses.map(w=>({pin:sha(spki(w.ec)),publicKey:spki(w.ec).toString('base64url'),pqPin:sha(spki(w.pq)),pqPublicKey:spki(w.pq).toString('base64url')}));
 const wallets=['demo-alice','demo-bob','demo-person'].map(id=>{
  const ec=generateKeyPairSync('ec',{namedCurve:'prime256v1'}),pq=generateKeyPairSync('ml-dsa-65');
  const scope={signingPin:sha(spki(ec)),pqPin:sha(spki(pq))};
  const j=ec.publicKey.export({format:'jwk'}),point=Buffer.concat([Buffer.from([4]),Buffer.from(j.x,'base64url'),Buffer.from(j.y,'base64url')]);
  let proofs=[];
  return {policy:{id,scope,trustedAuthorities},proof(payee,cents,nonce=randomBytes(32).toString('hex')){
   const intent={Payee:payee,Cents:cents,Nonce:nonce,Issued:now,Expires:now+120000};
   const b=Buffer.from(JSON.stringify(['quantic-pay-native-simulation/v1',scope.signingPin,scope.pqPin,payee,cents,'EUR',nonce,now,now+120000,false]));
   const p={intent,...scope,realPaymentAuthorized:false,classicalPublic:point.toString('base64url'),pqPublic:spki(pq).toString('base64url'),classicalSignature:sign('sha256',b,{key:ec.privateKey,dsaEncoding:'ieee-p1363'}).toString('base64url'),pqSignature:sign(null,b,pq.privateKey).toString('base64url')};
   proofs=[...proofs,p];return this.evidence(nonce);
  },evidence(nonce){
   const request=newPayCheckpointRequest(scope,now);
   const attestations=witnesses.map(w=>attestPayCheckpoint({retainedProofs:proofs,request,authorityPrivateKey:w.ec.privateKey,authorityPQPrivateKey:w.pq.privateKey,now}));
   return {payer:id,localProofs:proofs,nonce,request,attestations};
  }};
 });
 const options={directory:join(root,'ledger'),wallets:wallets.map(w=>w.policy),clock:()=>now};let db;
 try{
  assert.throws(()=>openMultiwalletLab(options));
  db=openMultiwalletLab({...options,createNew:true});
  const a=wallets[0].proof('demo-person',2500),b=wallets[1].proof('demo-shop',500),c=wallets[2].proof('demo-shop',1000);
  assert.throws(()=>db.settle({...a,payer:'demo-bob'}));
  assert.throws(()=>db.settle({...a,attestations:a.attestations.slice(0,2)}));
  const receipt=db.settle(a);db.settle(b);db.settle(c);
  assert.deepEqual(db.snapshot().balances,{'demo-alice':7500,'demo-bob':9500,'demo-person':11500,'demo-shop':1500});
  assert.equal(db.snapshot().totalCents,30000);
  assert.deepEqual(db.settle(a),receipt);assert.equal(db.snapshot().transferCount,3);
  db.close();db=openMultiwalletLab(options);assert.deepEqual(db.lookup(a.nonce),receipt);
  assert.throws(()=>db.settle(wallets[1].proof('demo-shop',1,a.nonce)));
  assert.throws(()=>db.settle(wallets[2].proof('demo-person',1)));
  assert.throws(()=>db.settle(wallets[0].proof('demo-shop',8000)));
  assert.equal(db.snapshot().transferCount,3);
  assert.throws(()=>openMultiwalletLab({...options,wallets:[options.wallets[1],{...options.wallets[0],id:'demo-alice',scope:options.wallets[2].scope},options.wallets[2]]}));
 }finally{db?.close();rmSync(root,{recursive:true,force:true});}
});
