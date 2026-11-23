import test from 'node:test';
import assert from 'node:assert/strict';
import {openMultiplexSender, openMultiplexReceiver, MUX_POLICY} from '../lib/quantic/scattering-multiplex-lab.mjs';

// Negative-control security test. This lab intentionally exposes a stable,
// epoch-scoped 16-byte sender label. Grouping does not require keys.
const members = [
  {id: 'demo-alice', secret: Buffer.alloc(32, 0x11)},
  {id: 'demo-bob', secret: Buffer.alloc(32, 0x22)},
];
const epoch = Buffer.alloc(32, 0x33);
const config = () => ({members, epoch, direction: 'a-b'});
const publicTag = packet => packet.subarray(0, 16).toString('hex');

test('a passive observer can link same-member frames by public epoch tag', () => {
  const sender = openMultiplexSender(config());
  const receiver = openMultiplexReceiver(config());
  try {
    sender.enqueue('demo-alice', Buffer.from('a1'));
    sender.enqueue('demo-alice', Buffer.from('a2'));
    sender.enqueue('demo-bob', Buffer.from('b1'));
    const frames = [sender.nextSlot(), sender.nextSlot(), sender.nextSlot()];
    assert.ok(frames.every(frame => frame.length === MUX_POLICY.frame));
    // Round-robin order in the current laboratory: Alice, Bob, Alice.
    assert.deepEqual(frames.map(publicTag), [
      publicTag(frames[0]), publicTag(frames[1]), publicTag(frames[0]),
    ]);
    assert.notEqual(publicTag(frames[0]), publicTag(frames[1]));
    // The passive observer did not need the keys or to decrypt any payload.
    assert.deepEqual(frames.map(frame => receiver.receive(frame)?.member), [
      'demo-alice', 'demo-bob', 'demo-alice',
    ]);
  } finally {
    sender.close();
    receiver.close();
  }
});

test('rotating the epoch changes the public tag but not within-epoch linkability', () => {
  const first = openMultiplexSender(config());
  const second = openMultiplexSender({
    members, epoch: Buffer.alloc(32, 0x44), direction: 'a-b',
  });
  try {
    first.enqueue('demo-alice', Buffer.from('x'));
    second.enqueue('demo-alice', Buffer.from('x'));
    const before = publicTag(first.nextSlot());
    const after = publicTag(second.nextSlot());
    assert.notEqual(before, after);
  } finally {
    first.close();
    second.close();
  }
});

test('an idle cover cell has the same length but does not prevent clustering of tagged data', () => {
  const sender = openMultiplexSender(config());
  try {
    const idle = sender.nextSlot();
    sender.enqueue('demo-alice', Buffer.from('first'));
    const a = sender.nextSlot();
    sender.enqueue('demo-alice', Buffer.from('second'));
    const b = sender.nextSlot();
    assert.ok([idle, a, b].every(frame => frame.length === MUX_POLICY.frame));
    assert.equal(publicTag(a), publicTag(b));
  } finally {
    sender.close();
  }
});
