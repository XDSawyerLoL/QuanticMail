import assert from 'node:assert/strict';
import test from 'node:test';
import {
 PRIME,SHARE_COUNT,THRESHOLD,shares,evaluate,reconstructThree,
 compatibleSecretCounts,independentEpochCounts,exhaustiveTwoShareSecurity,
 exhaustiveThreeShareRecovery,refreshDemo,runProofWitness
} from '../labs/quantic-native/scattering/threshold-secrecy-proof-v07.mjs';

test('ten position pairs, all 17 secrets and 17 squared polynomials: equal two-share distributions',()=>{
 const report=exhaustiveTwoShareSecurity();
 assert.equal(report.checkedExperiments,10*17**3);
 assert.equal(report.allTwoShareViewsExactlyUniform,true);
 assert.equal(report.maxInformationLeakBitsForThisModel,0);
});
test('all 3-of-5 combinations reconstruct correctly for all toy secrets and coefficient pairs',()=>{
 const report=exhaustiveThreeShareRecovery();
 assert.equal(report.checkedExperiments,10*17**3);
 assert.equal(report.allThreeShareReconstructionsExact,true);
});
test('one observed share has exactly 17 completions for each possible secret',()=>{
 const observed=[shares(7,3,2)[0]];
 assert.deepEqual(compatibleSecretCounts(observed),Array(PRIME).fill(PRIME));
});
test('two same-epoch shares have one completion for each possible secret',()=>{
 const observed=[shares(7,3,2)[0],shares(7,3,2)[1]];
 assert.deepEqual(compatibleSecretCounts(observed),Array(PRIME).fill(1));
});
test('two shares in two independent epochs do not distinguish candidate secrets',()=>{
 const old=shares(7,3,2),current=shares(7,9,5);
 assert.deepEqual(independentEpochCounts([[old[0],old[1]],[current[2],current[3]]]),Array(PRIME).fill(1));
});
test('two old plus one new share remain perfectly ambiguous under independent refresh',()=>{
 const old=shares(7,3,2),current=shares(7,9,5);
 assert.deepEqual(independentEpochCounts([[old[0],old[1]],[current[2]]]),Array(PRIME).fill(PRIME));
});
test('no refresh allows attacker to combine captures from different periods to reconstruct secret',()=>{
 const old=shares(7,3,2);
 assert.equal(reconstructThree([old[0],old[1],old[2]]),7);
 const demo=refreshDemo();
 assert.equal(demo.staticEpochThresholdReconstruction,7);
 assert.notEqual(demo.guessedSecretAfterMixedEpochInterpolation,7);
 assert.equal(demo.compatibleCandidateSecrets,PRIME);
});
test('compromising three current-epoch shares always reveals secret',()=>{
 assert.equal(refreshDemo().activeEpochThresholdReconstruction,7);
});
test('reject duplicate indices, invalid entries, bad thresholds or unsafe metadata',()=>{
 assert.equal(SHARE_COUNT,5);assert.equal(THRESHOLD,3);
 const list=shares(7,3,2);
 assert.throws(()=>reconstructThree(list.slice(0,2)),/Require exactly 3/);
 assert.throws(()=>reconstructThree([list[0],list[0],list[2]]),/Duplicate/);
 assert.throws(()=>compatibleSecretCounts([{x:1,y:3,privateKey:'x'}]),/x and y only/);
 assert.throws(()=>evaluate(17,1,1,1),/Invalid field value/);
 assert.throws(()=>independentEpochCounts([]),/Require 1..20/);
});
test('proof witness is reproducible and does not claim end-to-end security or 99.99999%',()=>{
 const first=runProofWitness();
 assert.deepEqual(first,runProofWitness());
 assert.equal(first.actualProductionCryptography,false);
 assert.equal(first.wholeSystemSecurity9999999Proven,false);
 assert.equal(first.releaseAuthorized,false);
 assert.equal(first.secretSharingProtocolImplemented,false);
});
