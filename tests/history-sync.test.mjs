import test from "node:test";
import assert from "node:assert/strict";
import { localMessageFromEnvelope } from "../lib/quantic/message-core.mjs";

const sender = "alice~0123456789abcdef0123456789abcdef@quantic";
const recipient = "bob~abcdef0123456789abcdef0123456789@quantic";

function payload(overrides = {}) {
  return {
    id: "logical-message-0001",
    from: sender,
    to: recipient,
    subject: "Bonjour",
    body: "Message",
    createdAt: "2026-09-16T18:00:00.000Z",
    ...overrides,
  };
}

test("normal recipient delivery is stored as incoming", () => {
  const result = localMessageFromEnvelope(payload(), {
    from: sender,
    to: recipient,
    createdAt: "2026-09-16T18:00:01.000Z",
  });
  assert.equal(result.direction, "in");
  assert.equal(result.id, "logical-message-0001");
  assert.equal(result.to, recipient);
});

test("sync copy transported to sender identity is stored as outgoing", () => {
  const result = localMessageFromEnvelope(payload({ syncCopy: true }), {
    from: sender,
    to: sender,
    createdAt: "2026-09-16T18:00:01.000Z",
  });
  assert.equal(result.direction, "out");
  assert.equal(result.id, "logical-message-0001");
  assert.equal(result.to, recipient);
});

test("sync copy is rejected when transport is not addressed back to sender identity", () => {
  assert.throws(
    () => localMessageFromEnvelope(payload({ syncCopy: true }), {
      from: sender,
      to: recipient,
      createdAt: "2026-09-16T18:00:01.000Z",
    }),
    /sync/i,
  );
});
