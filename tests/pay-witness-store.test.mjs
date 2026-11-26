import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,rmSync,realpathSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {generateKeyPairSync,createHash,randomBytes,sign} from 'node:crypto';
import {openPayWitnessStore} from '../lib/quantic/pay-witness-store.mjs';
import {newPayCheckpointRequest,summarizePayProofs} from '../lib/quantic/pay-lab-checkpoint.mjs';
const sha=b=>createHash('sha256').update(b).digest('hex');
const spki=k=>k.publicKey.export({format:'der',type:'spki'});
test('private witness store reopens history, refuses duplicate, stale prior and wrong key; never creates on missing reopen',{skip:process.platform!=='linux'},()=>{
 const dir=realpathSync(mkdtempSync(join(tmpdir(),'pay-witness-')));
 const ec=generateKeyPairSync('ec',{namedCurve:'prime256v1'}),pq=generateKeyPairSync('ml-dsa-65'),w=generateKeyPairSync('ed25519'),wq=generateKeyPairSync('ml-dsa-65');
 const scope={signingPin:sha(spki(ec)),pqPin:sha(spki(pq))},now=123456;
 const directory=join(dir,'witness'),options={directory,scope,authorityPrivateKey:w.privateKey,expectedAuthorityPin:sha(spki(w)),authorityPQPrivateKey:wq.privateKey,expectedAuthorityPQPin:sha(spki(wq)),clock:()=>now};
 const j=ec.publicKey.export({format:'jwk'}),point=Buffer.concat([Buffer.from([4]),Buffer.from(j.x,'base64url'),Buffer.from(j.y,'base64url')]);
 function proof(cents){
  const i={Payee:'demo-shop',Cents:cents,Nonce:randomBytes(32).toString('hex'),Issued:now,Expires:now+120000};
  const b=Buffer.from(JSON.stringify(['quantic-pay-native-simulation/v1',scope.signingPin,scope.pqPin,i.Payee,i.Cents,'EUR',i.Nonce,i.Issued,i.Expires,false]));
  return {intent:i,...scope,realPaymentAuthorized:false,classicalPublic:point.toString('base64url'),pqPublic:spki(pq).toString('base64url'),classicalSignature:sign('sha256',b,{key:ec.privateKey,dsaEncoding:'ieee-p1363'}).toString('base64url'),pqSignature:sign(null,b,pq.privateKey).toString('base64url')};
 }
 let store;
 try{
  assert.throws(()=>openPayWitnessStore(options));
  store=openPayWitnessStore({...options,createNew:true});
  const first=proof(250),empty=summarizePayProofs([],scope),after=store.append(first,empty);
  assert.equal(after.count,1);store.close();store=openPayWitnessStore(options);
  assert.deepEqual(store.summary(),after);
  assert.equal(store.vote(newPayCheckpointRequest(scope,now)).payload.root,after.root);
  assert.throws(()=>store.append(first,after));
  assert.throws(()=>store.append(proof(1),empty));
  assert.throws(()=>store.append(proof(10000),after));
  assert.deepEqual(store.summary(),after);
  assert.throws(()=>openPayWitnessStore({...options,createNew:true}));
  assert.throws(()=>openPayWitnessStore({...options,authorityPrivateKey:generateKeyPairSync('ed25519').privateKey}));
  assert.throws(()=>openPayWitnessStore({...options,authorityPQPrivateKey:generateKeyPairSync('ml-dsa-65').privateKey}));
 }finally{store?.close();rmSync(dir,{recursive:true,force:true});}
});
