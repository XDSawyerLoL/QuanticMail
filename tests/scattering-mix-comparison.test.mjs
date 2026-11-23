import test from 'node:test';
import assert from 'node:assert/strict';
import {CELL_BYTES, compareSchedules, generateArrivals, simulateSchedule} from '../lib/quantic/scattering-mix-comparison-lab.mjs';

const cfg = {ticks: 240, tickMs: 50, cellsPerTick: 2, batchTicks: 8,
  seed: 123, arrivalProbability: 0.15, burstCells: 4};

test('comparisons are deterministic and preserve every admitted cell', () => {
  const result = compareSchedules(cfg);
  assert.deepEqual(result, compareSchedules(cfg));
  assert.equal(result.results.length, 3);
  for (const r of result.results) {
    assert.equal(r.admitted + r.dropped, r.arrivals);
    assert.equal(r.sent + r.unsent, r.admitted);
    assert.ok(r.cellsOnWire * CELL_BYTES >= 0);
    assert.ok(r.coverCells >= 0);
    assert.ok(r.delayP95ms === null || r.delayP95ms >= 0);
  }
});
test('fixed and hybrid wire packet counts cannot distinguish activity from idle', () => {
  const x = compareSchedules(cfg);
  assert.deepEqual(x.observer, [
    {mode: 'fixed-cover', wireCountTracesIdentical: true},
    {mode: 'batch-no-cover', wireCountTracesIdentical: false},
    {mode: 'hybrid-cover-batch', wireCountTracesIdentical: true},
  ]);
  assert.equal(x.results[0].cellsOnWire, cfg.ticks * cfg.cellsPerTick);
  assert.equal(x.results[2].cellsOnWire, cfg.ticks * cfg.cellsPerTick);
  assert.ok(x.results[1].cellsOnWire < x.results[0].cellsOnWire);
  assert.ok(x.results[1].maxCellsInTick > cfg.cellsPerTick);
});
test('idle batch sends zero; two cover schemes keep a fixed cadence', () => {
  const idle = Array(cfg.ticks).fill(0);
  assert.equal(simulateSchedule('batch-no-cover', cfg, idle).cellsOnWire, 0);
  for (const mode of ['fixed-cover','hybrid-cover-batch']) {
    const r = simulateSchedule(mode, cfg, idle);
    assert.equal(r.cellsOnWire, cfg.ticks * cfg.cellsPerTick);
    assert.equal(r.coverCells, r.cellsOnWire);
  }
});
test('queue limit and overload do not silently discard admitted cells', () => {
  const overloaded = {...cfg, queueLimit: 5, arrivalProbability: 1, burstCells: 8};
  for (const mode of ['fixed-cover','batch-no-cover','hybrid-cover-batch']) {
    const r = simulateSchedule(mode, overloaded);
    assert.ok(r.dropped > 0);
    assert.ok(r.maxQueue <= overloaded.queueLimit);
    assert.equal(r.sent + r.unsent + r.dropped, r.arrivals);
  }
});
test('reject malformed inputs and unknown modes', () => {
  assert.throws(() => generateArrivals({...cfg, arrivalProbability: 1.2}));
  assert.throws(() => simulateSchedule('unknown', cfg));
  assert.throws(() => simulateSchedule('fixed-cover', cfg, Array(cfg.ticks).fill(-1)));
});
