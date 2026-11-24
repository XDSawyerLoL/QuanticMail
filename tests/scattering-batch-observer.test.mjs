import test from 'node:test';
import assert from 'node:assert/strict';
import {studyObserver, compareObserverScenarios} from '../lib/quantic/scattering-batch-observer-lab.mjs';

test('deterministic model and source probabilities in range', () => {
  const p = {seed: 7, users: 8, ticks: 500, probability: 0.12, windowTicks: 8};
  const result = studyObserver(p);
  assert.deepEqual(result, studyObserver(p));
  assert.ok(result.arrivals > 0);
  assert.ok(result.idealizedSourceGuessRate > 0 && result.idealizedSourceGuessRate <= 1);
  assert.equal(result.mappedTagSourceGuessRate, 1);
});
test('zero traffic has no arbitrary anonymity score', () => {
  const r = studyObserver({probability: 0});
  assert.equal(r.arrivals, 0);
  assert.equal(r.idealizedSourceGuessRate, null);
  assert.equal(r.mappedTagSourceGuessRate, null);
});
test('a very dominant sender remains highly attributable even after batching', () => {
  const r = studyObserver({users: 12, probability: 0.01, dominantMultiplier: 100,
    ticks: 1600, windowTicks: 32, seed: 11});
  assert.ok(r.idealizedSourceGuessRate > 0.5);
});
test('under balanced loads, larger batches reduce idealized source guessing', () => {
  const p = {users: 12, ticks: 6400, probability: 0.06, seed: 99};
  const a = studyObserver({...p, windowTicks: 1});
  const b = studyObserver({...p, windowTicks: 32});
  assert.equal(a.arrivals, b.arrivals);
  assert.ok(b.idealizedSourceGuessRate < a.idealizedSourceGuessRate);
});
test('sparse groups are more attributable than busy balanced groups', () => {
  const sparse = studyObserver({probability: 0.005, seed: 17, ticks: 6400, windowTicks: 8});
  const busy = studyObserver({probability: 0.06, seed: 17, ticks: 6400, windowTicks: 8});
  assert.ok(sparse.idealizedSourceGuessRate > busy.idealizedSourceGuessRate);
});
test('reject unrealistic or malformed parameters', () => {
  assert.throws(() => studyObserver({probability: 0.2, dominantMultiplier: 8}));
  assert.throws(() => studyObserver({users: 1}));
  assert.throws(() => studyObserver({ticks: Infinity}));
  assert.throws(() => compareObserverScenarios({trials: 1}));
});
test('multi-trial confidence report is reproducible and bounded', () => {
  const a = compareObserverScenarios({trials: 4, ticks: 640, seed: 11});
  assert.deepEqual(a, compareObserverScenarios({trials: 4, ticks: 640, seed: 11}));
  assert.equal(a.results.length, 9);
  for (const row of a.results) {
    assert.ok(row.lower95 <= row.mean && row.mean <= row.upper95);
    assert.ok(row.mean >= 0 && row.mean <= 1);
    assert.equal(row.mappedTagGuessRate, 1);
  }
});
