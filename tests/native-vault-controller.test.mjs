import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,createHash,verify,createHmac,diffieHellman,createPublicKey,sign} from 'node:crypto';
import {controllerFrame,normalizeClassicalEnvelope,connectNativeVault,newBrokerSessionChallenge,parseNativeReply,nativeControllerFrame} from '../desktop/native-vault-controller.mjs';
test('native IPC frame binds exact bytes, nonce and sequence',()=>{
 const k=generateKeyPairSync('ed25519'),nonce=Buffer.alloc(32,5),body={op:'public'};
 const f=JSON.parse(controllerFrame(nonce,1,body,k.privateKey));
 const b=Buffer.from(f.body,'base64url'),s=Buffer.from(f.sig,'base64url'),seq=Buffer.alloc(4);seq.writeUInt32BE(1);
 const digest=()=>createHash('sha256').update(Buffer.concat([Buffer.from('quantic-vault-controller-lab/v1\0'),nonce,seq,b])).digest();
 assert.ok(verify(null,digest(),k.publicKey,s));seq.writeUInt32BE(2);assert.ok(!verify(null,digest(),k.publicKey,s));
 assert.throws(()=>controllerFrame(nonce,257,body,k.privateKey));
});
test('static compatibility refuses hybrid, prekeys and private key fields',()=>{
 const p=generateKeyPairSync('ec',{namedCurve:'prime256v1'});
 const e={keyMode:'static-fallback',ephemeralPublicKey:p.publicKey.export({format:'jwk'}),iv:Buffer.alloc(12).toString('base64'),ciphertext:Buffer.alloc(16).toString('base64')};
 assert.deepEqual(normalizeClassicalEnvelope(e).ephemeralPublicKey,e.ephemeralPublicKey);
 for(const change of [{keyMode:'one-time-prekey'},{preKeyId:'x'},{cryptoSuite:'hybrid'},{hybrid:true},{ephemeralPublicKey:p.privateKey.export({format:'jwk'})},{iv:'not base64'},{keyMode:undefined}])assert.throws(()=>normalizeClassicalEnvelope({...e,...change}));
});
test('native controller has no implicit activation or legacy fallback',async()=>{
 await assert.rejects(connectNativeVault({labOnly:false}),/laboratory/);
 await assert.rejects(connectNativeVault({labOnly:true,binary:'relative'}));
});

test('explicit PQ controller refuses incomplete configuration before spawn',async()=>{
 await assert.rejects(connectNativeVault({labOnly:true,pqMode:{enabled:true}}));
});

test('broker must possess pinned private key; copied public keys and old proof are insufficient',()=>{
 const owner=generateKeyPairSync('ec',{namedCurve:'prime256v1'});
 const impostor=generateKeyPairSync('ec',{namedCurve:'prime256v1'});
 const point=k=>{const j=k.export({format:'jwk'});return Buffer.concat([Buffer.from([4]),Buffer.from(j.x,'base64url'),Buffer.from(j.y,'base64url')]);};
 function answer(challenge,key){
  const p=Buffer.from(challenge.peer,'base64url');
  const peer=createPublicKey({format:'jwk',key:{kty:'EC',crv:'P-256',x:p.subarray(1,33).toString('base64url'),y:p.subarray(33).toString('base64url')}});
  const secret=diffieHellman({privateKey:key,publicKey:peer});
  const prk=createHmac('sha256','quantic-vault-session-proof-extract/v1\0').update(secret).digest();
  return createHmac('sha256',prk).update('quantic-vault-session-proof/v1\0').update(p).update(point(owner.publicKey)).digest('base64url');
 }
 const valid=newBrokerSessionChallenge(owner.publicKey),proof=answer(valid,owner.privateKey);
 valid.verify(proof);assert.throws(()=>valid.verify(proof),/consumed/);
 const wrong=newBrokerSessionChallenge(owner.publicKey);assert.throws(()=>wrong.verify(answer(wrong,impostor.privateKey)),/mismatch/);
 const fresh=newBrokerSessionChallenge(owner.publicKey);assert.throws(()=>fresh.verify(proof),/mismatch/);
});

test('native reply parser clears owned bytes on success, malformed UTF-8 and invalid JSON',()=>{
 for(const bytes of [Buffer.from('{"ok":true,"message":"synthetic secret"}'),Buffer.from('{bad'),Buffer.from([0xc0,0xaf]),Buffer.from('[]')]){
  if(bytes[0]===123&&bytes[1]===34)assert.equal(parseNativeReply(bytes).ok,true);
  else assert.throws(()=>parseNativeReply(bytes));
  assert.ok(bytes.every(b=>b===0),'reply bytes retained');
 }
});

test('native signer interoperates with existing protocol and clears input',async()=>{
 const pair=generateKeyPairSync('ed25519'),nonce=Buffer.alloc(32,7),body={op:'public'};
 let input;
 const signFrame=async b=>{input=b;return sign(null,createHash('sha256').update('quantic-vault-controller-lab/v1\0').update(b).digest(),pair.privateKey);};
 assert.equal(await nativeControllerFrame(nonce,1,body,pair.publicKey,signFrame),controllerFrame(nonce,1,body,pair.privateKey));
 assert.ok(input.every(b=>b===0));
 await assert.rejects(nativeControllerFrame(nonce,1,body,pair.publicKey,async()=>Buffer.alloc(64)),/signature refused/);
});
