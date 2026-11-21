import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,createHash,verify} from 'node:crypto';
import {controllerFrame,normalizeClassicalEnvelope,connectNativeVault} from '../desktop/native-vault-controller.mjs';
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
