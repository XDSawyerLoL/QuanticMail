import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {verifyNativeEnrollmentRequest} from '../desktop/native-enrollment-claim.mjs';
const fixture=process.env.QUANTIC_ENROLLMENT_TEST_OUTPUT;
test('real Go/OpenSSL native enrollment request verifies in Node Quantic identity bridge, rejects tampering', {skip:!fixture}, ()=>{
 const r=JSON.parse(readFileSync(fixture,'utf8'));
 const opts={quorumPin:'c'.repeat(64)};
 const result=verifyNativeEnrollmentRequest(r,opts);
 assert.equal(result.status,'valid-public-claim-pending-independent-approval');
 assert.equal(result.remotelyEnrolled,false);
 assert.equal(result.mailAuthorized,false);
 for(const mutate of [
  x=>{x.claim.remotelyEnrolled=true},
  x=>{x.claim.mailAuthorized=true},
  x=>{x.claim.signingPin=x.claim.rootPin},
  x=>{x.claim.address='substituted~'+'a'.repeat(32)+'@quantic'},
  x=>{x.claim.profile.payload.policy='transition'},
  x=>{x.controllerPublic=Buffer.alloc(32,1).toString('base64url')},
  x=>{x.ownerMlDsaSignature=Buffer.alloc(3309,0).toString('base64url')},
  x=>{x.ownerP256Signature=Buffer.alloc(64,0).toString('base64')},
 ]){const b=structuredClone(r);mutate(b);assert.throws(()=>verifyNativeEnrollmentRequest(b,opts));}
 assert.throws(()=>verifyNativeEnrollmentRequest(r,{quorumPin:'d'.repeat(64)}));
 assert.throws(()=>verifyNativeEnrollmentRequest(r,{...opts,now:Date.now()+25*3600*1000}));
});
