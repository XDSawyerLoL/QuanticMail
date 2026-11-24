import test from 'node:test';
import assert from 'node:assert/strict';
import {traceMetrics, summarizePairs} from '../lib/quantic/scattering-wire-metrics.mjs';

test('counts valid 168-byte UDP traffic and computes real interarrival gaps', () => {
  assert.deepEqual(traceMetrics([0,20,40,60],[168,168,168,168],20), {
    received:4,bytes:672,length168:4,unexpectedLengths:0,medianGapMs:20,
    p95GapMs:20,p99GapMs:20,maxGapMs:20,gapsOver2Periods:0,
  });
});
test('records long pauses, unexpected lengths and empty traces without invented samples', () => {
  const r=traceMetrics([0,20,100],[168,160,168],20);
  assert.equal(r.gapsOver2Periods,1);
  assert.equal(r.unexpectedLengths,1);
  assert.equal(r.p95GapMs,80);
  assert.equal(traceMetrics([],[],20).medianGapMs,null);
});
test('refuses invalid and out-of-order timestamps', () => {
  assert.throws(()=>traceMetrics([1,0],[168,168],20));
  assert.throws(()=>traceMetrics([1],[168,168],20));
  assert.throws(()=>traceMetrics([1],[168],0));
  assert.throws(()=>summarizePairs([]));
});
test('paired deltas are descriptive and deterministic', () => {
  const pairs = [
    {idle:{rx:{received:100,medianGapMs:20,p95GapMs:21}},busy:{rx:{received:99,medianGapMs:21,p95GapMs:23}}},
    {idle:{rx:{received:97,medianGapMs:22,p95GapMs:24}},busy:{rx:{received:99,medianGapMs:21,p95GapMs:25}}},
  ];
  const r=summarizePairs(pairs);
  assert.equal(r.pairs,2);
  assert.equal(r.avgReceiverCountDifferenceBusyMinusIdle,.5);
  assert.equal(r.avgMedianGapDifferenceMs,0);
  assert.equal(r.avgP95GapDifferenceMs,1.5);
});
