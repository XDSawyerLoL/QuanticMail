import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import test from 'node:test';

import { evaluateTrafficLeakage } from '../labs/quantic-native/scattering/traffic-privacy-lab.mjs';
import { reliableCellStream, openReliable } from '../labs/quantic-native/scattering/scattering-reliable-lab.mjs';

test('native-compatible fixed-batch lab carrier emits equal public size/timing metadata for cover and content', () => {
  const sendKey = randomBytes(32);
  const receiveKey = randomBytes(32);
  let now = 0;
  const records = [];
  let published = 0;
  const carrier = reliableCellStream({
    sendKey,
    recvKey: receiveKey,
    autoTick: false,
    compactPacing: true,
    clock: () => now,
    publish: (packets) => {
      published++;
      assert.equal(packets.length, 2);
      packets.forEach((packet, index) => {
        const decrypted = openReliable(sendKey, packet);
        assert.ok(decrypted);
        records.push({
          kind: decrypted.seq === null ? 'cover' : 'real',
          packetBytes: packet.length,
          // Synthetic slot spacing, not a physical-network timing measurement.
          gapMs: index === 0 ? 50 : 0,
          direction: 'out',
        });
      });
      return true;
    },
  });
  carrier.stream.on('error', () => {});
  try {
    for (let tick = 0; tick < 40; tick++) {
      now = tick * 50;
      carrier.tick(); // 80 cover cells
    }
    carrier.stream.write(Buffer.alloc(8192, 0x52), () => {});
    for (let tick = 40; tick < 80; tick++) {
      now = tick * 50;
      carrier.tick(); // at least 64 real cells, then retries
    }
    const countReal = records.filter(r => r.kind === 'real').length;
    const countCover = records.filter(r => r.kind === 'cover').length;
    assert.ok(countReal >= 32);
    assert.ok(countCover >= 32);
    assert.equal(published, 80);
    assert.ok(records.every(r => r.packetBytes === 168));
    const report = evaluateTrafficLeakage(records, { permutations: 199 });
    // Finite train/test splits can fluctuate around 50%; do not demand exact equality.
    assert.ok(Math.abs(report.balancedAccuracy - 0.5) <= 0.15);
    assert.ok(report.permutationPValue > 0.05);
    assert.equal(report.potentialLeakageDetected, false);
    assert.match(report.conclusion, /not an anonymity proof/);
  } finally {
    carrier.stream.destroy();
  }
});
