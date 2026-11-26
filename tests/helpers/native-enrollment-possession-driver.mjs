// One test-only operator process. No production authorities or accounts.
import {createInterface} from 'node:readline';
import {generateKeyPairSync,createHash,createPublicKey} from 'node:crypto';
import assert from 'node:assert/strict';
import {prepareNativePossessionChallenge} from '../../desktop/native-enrollment-possession.mjs';
import {enrollmentRosterPin} from '../../desktop/native-enrollment-quorum.mjs';
const io=createInterface({input:process.stdin,crlfDelay:Infinity});
const lines=io[Symbol.asyncIterator]();
try{
 const request=JSON.parse((await lines.next()).value);
 const keys=Array.from({length:4},()=>generateKeyPairSync('ed25519').privateKey);
 const trusted=keys.map(key=>{const d=createPublicKey(key).export({format:'der',type:'spki'});return {pin:createHash('sha256').update(d).digest('hex'),publicKey:d.toString('base64url')};});
 const authorityKey=keys[0],expectedAuthorityPin=trusted[0].pin,rosterPin=enrollmentRosterPin(trusted);
 const opts={quorumPin:'c'.repeat(64),authorityKey,expectedAuthorityPin,trusted,rosterPin};
 const proof=prepareNativePossessionChallenge(request,opts);
 process.stdout.write(JSON.stringify({challenge:proof.challenge,operatorPin:expectedAuthorityPin})+'\n');
 const response=JSON.parse((await lines.next()).value);
 const result=proof.verify(response,{approved:true,approveEnrollment:true});
 assert.equal(result.status,'device-possession-verified-pending-authority-renewal');
 assert.equal(result.policyCandidate.active,false);
 assert.equal(result.mailAuthorized,false);
 assert.equal(result.vote.payload.rosterPin,rosterPin);
 assert.equal(result.vote.payload.authorityPin,expectedAuthorityPin);
 assert.throws(()=>proof.verify(response,{approved:true}));
 const refused=prepareNativePossessionChallenge(request,opts);
 assert.throws(()=>refused.verify(response,{approved:false}));
 assert.throws(()=>refused.verify(response,{approved:true}));
 const wrong=prepareNativePossessionChallenge(request,opts);
 assert.throws(()=>wrong.verify(response,{approved:true}));
 process.stdout.write(JSON.stringify(result)+'\n');
}finally{io.close();}
