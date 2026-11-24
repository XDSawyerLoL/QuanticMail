import test from 'node:test';
import assert from 'node:assert/strict';
import {scoreAttributionGuesses} from '../lib/quantic/scattering-fifo-timing-observer.mjs';
import {summarizeRepeatedRuns} from '../lib/quantic/scattering-repeat-summary-lab.mjs';

test('minority-only leakage survives a low aggregate accuracy',()=>{
 const truth=[...Array(100).fill('A'),...Array(20).fill('B'),...Array(430).fill(null)];
 const guess=[...Array(100).fill(null),...Array(20).fill('B'),...Array(430).fill(null)];
 const x=scoreAttributionGuesses(guess,truth);
 assert.equal(x.data.accuracyOverAll,.166667);
 assert.equal(x.sourceMetrics.B.recall,1);
 assert.equal(x.sourceMetrics.B.precisionIncludingCover,1);
 assert.equal(x.sourceMetrics.balancedRecall,.5);
 assert.equal(x.confusion.A.abstain,100);
});
function fixture(i,{batch=8,b=100,leak=false,delay=300}={}){
 const truth=[...Array(100).fill('A'),...Array(b).fill('B'),...Array(450-b).fill(null)];
 const guesses=leak?truth.slice():truth.map((x,j)=>x===null?null:(j%2?'A':'B'));
 const score=scoreAttributionGuesses(guesses,truth);
 return {releaseReady:false,sharedHostFileSystemAccess:true,
  sourceBRealMessagesRequested:b,batchSizeRequested:batch||null,
  sourceOffsetRequestedMs:i%2?25:0,measuredFirstSourceOffsetMs:i%2?24.3:1.2,
  native:{planned:550,sent:550,missed:0},
  receiver:{authenticatedE2E:100+b,perSender:{A:100,B:b},replays:0},
  x:{egress:{matchedUnique:0}},
  timeOnlyObserver:{attackerKeysProvided:false,oracleKeysUsedForScoringOnly:true,truth:{A:100,B:b},
   authenticatedMessageDelayMs:{count:100+b,p50:100,p95:delay,max:delay+20,truthKeysNeverGivenToAttacker:true},
   fifoQueueTimingAttack:{scenarios:[0,5,12].map(processingSlackMs=>({processingSlackMs,...score}))}}
 };
}
test('report worst repeat rather than averaging away a complete leak',()=>{
 const runs=Array.from({length:5},(_,i)=>fixture(i,{leak:i===4}));
 const summary=summarizeRepeatedRuns(runs,{batchSize:8,bReal:100});
 assert.equal(summary.authenticatedTotal,1000);
 assert.equal(summary.worstAttack.balancedRecall,1);
 assert.equal(summary.screening.privacy,false);
 assert.equal(summary.screening.candidate,false);
 assert.equal(summary.screening.releaseAuthorized,false);
});
test('screen a bounded low-latency laboratory profile without authorizing release',()=>{
 const runs=Array.from({length:5},(_,i)=>fixture(i,{delay:350+i*5}));
 const summary=summarizeRepeatedRuns(runs,{batchSize:8,bReal:100});
 assert.equal(summary.latency.worstRunP95Ms,370);
 assert.equal(summary.screening.candidate,true);
 assert.equal(summary.screening.releaseAuthorized,false);
});
test('reject missing delivery, incomplete profiles or inconsistent confusion counts',()=>{
 const runs=Array.from({length:5},(_,i)=>fixture(i));
 assert.throws(()=>summarizeRepeatedRuns(runs.slice(1),{batchSize:8,bReal:100}),/repeat count/);
 runs[2].receiver.authenticatedE2E=199;
 assert.throws(()=>summarizeRepeatedRuns(runs,{batchSize:8,bReal:100}),/incomplete/);
 runs[2]=fixture(2);
 runs[3].timeOnlyObserver.fifoQueueTimingAttack.scenarios[0].confusion.B.A++;
 assert.throws(()=>summarizeRepeatedRuns(runs,{batchSize:8,bReal:100}),/inconsistent/);
});
