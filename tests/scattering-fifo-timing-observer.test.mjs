import test from 'node:test';
import assert from 'node:assert/strict';
import {reconstructFifoTiming,scoreAttributionGuesses}
 from '../lib/quantic/scattering-fifo-timing-observer.mjs';
test('FIFO chronology exposes a link even when nearest packet repeats the wrong source',()=>{
 const x=reconstructFifoTiming({sourceATimes:[100,200],sourceBTimes:[110,210],
  egressTimes:[90,125,145,225,245,275],processingSlackMs:5});
 assert.deepEqual(x.guesses,[null,'A','B','A','B',null]);
 assert.equal(x.ingressObserved,4);
 const scored=scoreAttributionGuesses(x.guesses,[null,'A','B','A','B',null]);
 assert.equal(scored.data.correct,4);
 assert.equal(scored.data.majorityBaseline,0.5);
 assert.equal(scored.cover.wronglyGuessedAsData,0);
});
test('processing slack is declared in advance, and lost packets cause attribution errors',()=>{
 const x=reconstructFifoTiming({sourceATimes:[100,150],sourceBTimes:[110,160],
   egressTimes:[120,140,170],processingSlackMs:10});
 assert.deepEqual(x.guesses,['A','B','A']);
 const score=scoreAttributionGuesses(x.guesses,['B','A','B']);
 assert.equal(score.data.wrong,3);
 assert.equal(score.data.accuracyOverAll,0);
});
test('report high majority baseline and false cover attribution honestly',()=>{
 const truth=[...Array(18).fill('A'),...Array(2).fill('B'),null,null];
 const guesses=[...Array(10).fill('A'),...Array(10).fill('B'),'A',null];
 const x=scoreAttributionGuesses(guesses,truth);
 assert.equal(x.data.majorityBaseline,0.9);
 assert.equal(x.data.correct,12);
 assert.equal(x.data.accuracyOverAll,0.6);
 assert.equal(x.cover.wronglyGuessedAsData,1);
 assert.equal(x.cover.falseSourceAttributionRate,.5);
});
test('refuses unsorted timestamps, invalid hold-time and mismatched truth',()=>{
 assert.throws(()=>reconstructFifoTiming({sourceATimes:[10,9],sourceBTimes:[],egressTimes:[20]}));
 assert.throws(()=>reconstructFifoTiming({sourceATimes:[1],sourceBTimes:[2],egressTimes:[3],processingSlackMs:-1}));
 assert.throws(()=>reconstructFifoTiming({sourceATimes:[1],sourceBTimes:[2],egressTimes:[NaN]}));
 assert.throws(()=>scoreAttributionGuesses(['A'],['B','A']));
 assert.throws(()=>scoreAttributionGuesses(['A'],['A']));
});
