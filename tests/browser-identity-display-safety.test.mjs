import test from 'node:test';
import assert from 'node:assert/strict';
import {publicIdentityView} from '../lib/quantic/public-identity-view.mjs';
test('the Vault React display model cannot contain private browser JWKs, PQ secrets or bearer tokens',()=>{
 const i={handle:'alice',address:'alice@quantic',canonicalAddress:'alice~'+ 'a'.repeat(32)+'@quantic',
  fingerprint:'a'.repeat(32),publicKey:{x:'public'},privateKey:{d:'secret'},
  signingPrivateKey:{d:'root'},deviceSigningPrivateKey:{d:'device'},
  pqc:{mlDsaPrivateKeyPkcs8:'PQ SECRET',mlKemPrivateKeyPkcs8:'PQ SECRET'},
  authToken:'BEARER_SECRET',manifest:{devices:[]},createdAt:'synthetic'};
 const v=publicIdentityView(i);
 assert.deepEqual(Object.keys(v).sort(),['address','canonicalAddress','fingerprint','handle'].sort());
 const json=JSON.stringify(v);
 for(const secret of ['BEARER_SECRET','secret','root','device','PQ SECRET'])assert.ok(!json.includes(secret),secret);
 assert.equal(Object.isFrozen(v),true);
 assert.throws(()=>publicIdentityView({}));
});
