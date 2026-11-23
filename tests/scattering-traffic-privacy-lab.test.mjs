import assert from 'node:assert/strict';
import test from 'node:test';
import { evaluateTrafficLeakage } from '../labs/quantic-native/scattering/traffic-privacy-lab.mjs';

function trace(count, lengthFn, gapFn) {
  return Array.from({ length: count }, (_, i) => ({
    kind: i < count / 2 ? 'real' : 'cover',
    packetBytes: lengthFn(i),
    gapMs: gapFn(i),
    direction: 'out',
  }));
}
test('identical metadata yields chance-level accuracy and no anonymity claim', () => {
  const result = evaluateTrafficLeakage(trace(200, () => 168, () => 20), { permutations: 199 });
  assert.equal(result.balancedAccuracy, 0.5);
  assert.equal(result.permutationPValue, 1);
  assert.equal(result.potentialLeakageDetected, false);
  assert.match(result.conclusion, /not an anonymity proof/);
});
test('one-byte size leak is detectable', () => {
  const result = evaluateTrafficLeakage(
    trace(240, i => i < 120 ? 168 : 169, () => 20),
    { permutations: 199 },
  );
  assert.equal(result.balancedAccuracy, 1);
  assert.ok(result.permutationPValue <= 0.01);
  assert.equal(result.potentialLeakageDetected, true);
  assert.equal(result.test.real, result.test.cover);
});
test('timing-only leak is detectable', () => {
  const result = evaluateTrafficLeakage(
    trace(240, () => 168, i => i < 120 ? 3 : 300),
    { permutations: 199 },
  );
  assert.equal(result.balancedAccuracy, 1);
  assert.equal(result.potentialLeakageDetected, true);
});
test('seeded experiments are reproducible', () => {
  const data = trace(120, () => 168, () => 20);
  assert.deepEqual(
    evaluateTrafficLeakage(data, { seed: 12, permutations: 199 }),
    evaluateTrafficLeakage(data, { seed: 12, permutations: 199 }),
  );
});
test('no payloads or identities are accepted in lab metadata', () => {
  const data = trace(120, () => 168, () => 20);
  assert.throws(() => evaluateTrafficLeakage([]), /32 real/);
  assert.throws(() => evaluateTrafficLeakage([...data, { ...data[0], ciphertext: 'private' }]), /Disallowed/);
  assert.throws(() => evaluateTrafficLeakage(data.map((r, i) => i ? r : { ...r, gapMs: NaN })), /gapMs/);
  assert.throws(() => evaluateTrafficLeakage(data.map((r, i) => i ? r : { ...r, direction: 'wrong' })), /direction/);
});
