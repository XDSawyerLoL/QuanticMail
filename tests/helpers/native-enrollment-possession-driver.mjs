// One test-only operator process. No production authorities or accounts.
import {createInterface} from 'node:readline';
import {generateKeyPairSync,createHash} from 'node:crypto';
import assert from 'node:assert/strict';
import {prepareNativePossessionChallenge} from '../../desktop/native-enrollment-possession.mjs';
const io=createInterface({input:process.stdin,crlfDelay:Infinity});
const lines=io[Symbol.asyncIterator]();
try{
 const request=JSON.parse((await lines.next()).value);
 const authorityKey=generateKeyPairSync('ed25519').privateKey;
 const expectedAuthorityPin=createHash('sha256').update((await import('node:crypto')).createPublicKey(authorityKey).export({format:'der',type:'spki'})).digest('hex');
 const opts={quorumPin:'c'.repeat(64),authorityKey,expectedAuthorityPin};
 const proof=prepareNativePossessionChallenge(request,opts);
 process.stdout.write(JSON.stringify({challenge:proof.challenge,operatorPin:expectedAuthorityPin})+'\n');
 const response=JSON.parse((await lines.next()).value);
 const result=proof.verify(response,{approved:true});
 assert.equal(result.status,'device-possession-verified-pending-authority-renewal');
 assert.equal(result.policyCandidate.active,false);
 assert.equal(result.mailAuthorized,false);
 assert.throws(()=>proof.verify(response,{approved:true}));
 const refused=prepareNativePossessionChallenge(request,opts);
 assert.throws(()=>refused.verify(response,{approved:false}));
 assert.throws(()=>refused.verify(response,{approved:true}));
 const wrong=prepareNativePossessionChallenge(request,opts);
 assert.throws(()=>wrong.verify(response,{approved:true}));
 process.stdout.write(JSON.stringify(result)+'\n');
}finally{io.close();}
