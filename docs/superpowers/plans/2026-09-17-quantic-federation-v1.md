# Quantic Federation V1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make two independent durable Quantic standalone relays exchange sender-authenticated opaque envelopes and delivery receipts without sharing user auth tokens or requiring Render/GitHub in the delivery path.

**Architecture:** Add portable signed envelopes, persistent relay identities, signed Route Manifests, direct relay-to-relay forwarding, replay/loop protection and signed federation receipts. The first implementation deliberately targets direct A→B federation; transit routing hooks are represented in the packet format but multi-hop discovery is implemented by the separate Discovery Mesh plan.

**Tech Stack:** Node.js 24+, TypeScript, Node `crypto`, existing Quantic P-256 identity/device model, native Node HTTP relay, atomic JSON relay state, `node:test`.

**Spec:** `docs/superpowers/specs/2026-09-16-quantic-network-federation-discovery-pqc-design.md`

## Global Constraints

- Preserve QuanticMail V1.1 canonical identities, including 32-hex new fingerprints and 10-hex legacy fingerprints.
- Do not modify the wire canonicalization of `quantic-identity-manifest` V1.
- User relay auth tokens remain relay-local and never appear in federation packets.
- Relays never receive plaintext or private identity/device keys.
- Federation packets and receipts are idempotent and reject rollback/replay.
- Direct federation works with Render and GitHub unavailable once required signed records are present locally.
- PQC fields remain optional in this plan; enforcement is added by the separate Crypto V2 plan.

---

### Task 1: Federation protocol canonicalization and portable envelope verification

**Files:**
- Create: `lib/quantic/federation-types.ts`
- Create: `lib/quantic/federation-core.mjs`
- Create: `lib/quantic/federation-core.d.mts`
- Test: `tests/federation-core.test.mjs`

**Interfaces:**
- Produces: `canonicalPortableEnvelopeText(envelope)`, `canonicalRouteManifestText(payload)`, `envelopeDigest(envelope)`, `validatePortableEnvelopeShape(envelope)`, `validateRouteManifestShape(manifest)`.
- Later tasks rely on these exact functions for signatures, replay keys and route validation.

- [ ] **Step 1: Write the failing canonicalization tests**

```js
import test from "node:test";
import assert from "node:assert/strict";
import {
  canonicalPortableEnvelopeText,
  canonicalRouteManifestText,
  envelopeDigest,
  validatePortableEnvelopeShape,
  validateRouteManifestShape,
} from "../lib/quantic/federation-core.mjs";

test("portable envelope canonicalization ignores signature values and is deterministic", async () => {
  const envelope = {
    format: "quantic-envelope",
    version: 2,
    clientMessageId: "msg-federation-0001",
    from: "alice~0123456789abcdef0123456789abcdef@quantic",
    fromDeviceId: "d-0123456789",
    to: "bob~abcdef0123456789abcdef0123456789@quantic",
    toDeviceId: "d-abcdef0123",
    keyMode: "v1-static-fallback",
    cryptoSuite: "QNT-P256-AES256GCM-1",
    classicalEphemeralPublicKey: { kty: "EC", crv: "P-256", x: "x", y: "y" },
    iv: "aXY=",
    ciphertext: "Y2lwaGVy",
    createdAt: "2026-09-17T00:00:00.000Z",
    expiresAt: "2026-09-18T00:00:00.000Z",
    signatures: { p256Device: "sig-one" },
  };
  const a = canonicalPortableEnvelopeText(envelope);
  const b = canonicalPortableEnvelopeText({ ...envelope, signatures: { p256Device: "sig-two" } });
  assert.equal(a, b);
  assert.equal(await envelopeDigest(envelope), await envelopeDigest({ ...envelope, signatures: { p256Device: "sig-two" } }));
});

test("route manifest canonicalization sorts relays by priority, relayId and endpoint", () => {
  const payload = {
    version: 1,
    sequence: 1,
    canonicalAddress: "bob~abcdef0123456789abcdef0123456789@quantic",
    identitySigningPublicKey: { kty: "EC", crv: "P-256", x: "ix", y: "iy" },
    identityManifestSequence: 2,
    cryptoProfileSequence: null,
    cryptoProfileDigest: null,
    relays: [
      { relayId: "b", endpoint: "https://b.example", priority: 20, protocols: ["quantic-federation/1"], classicalSigningPublicKey: { kty: "EC", crv: "P-256", x: "bx", y: "by" }, expiresAt: "2026-10-01T00:00:00.000Z" },
      { relayId: "a", endpoint: "https://a.example", priority: 10, protocols: ["quantic-federation/1"], classicalSigningPublicKey: { kty: "EC", crv: "P-256", x: "ax", y: "ay" }, expiresAt: "2026-10-01T00:00:00.000Z" },
    ],
    issuedAt: "2026-09-17T00:00:00.000Z",
    expiresAt: "2026-10-01T00:00:00.000Z",
  };
  const text = canonicalRouteManifestText(payload);
  assert.ok(text.indexOf("https://a.example") < text.indexOf("https://b.example"));
});

test("shape validators reject expired or malformed federation objects", () => {
  assert.throws(() => validatePortableEnvelopeShape({}), /enveloppe/i);
  assert.throws(() => validateRouteManifestShape({}), /route/i);
});
```

- [ ] **Step 2: Run tests and confirm RED**

Run: `node --test tests/federation-core.test.mjs`

Expected: FAIL because `lib/quantic/federation-core.mjs` does not exist.

- [ ] **Step 3: Implement deterministic canonicalization and validation**

Implement strict field validation, canonical address/device/message ID validation, deterministic relay sorting, and SHA-256 digesting via `globalThis.crypto.subtle.digest`. Do not verify signatures here; keep this module runtime-neutral.

- [ ] **Step 4: Run focused tests and full suite**

Run:

```bash
node --test tests/federation-core.test.mjs
npm test
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add lib/quantic/federation-types.ts lib/quantic/federation-core.mjs lib/quantic/federation-core.d.mts tests/federation-core.test.mjs
git commit -m "feat: define Quantic federation protocol core"
```

---

### Task 2: Persistent relay identity and signed hello handshake

**Files:**
- Create: `standalone-relay/identity.ts`
- Modify: `standalone-relay/server.ts`
- Modify: `standalone-relay/http.ts`
- Modify: `standalone-relay/storage.ts`
- Test: `tests/relay-identity.test.ts`
- Test: `tests/standalone-relay-federation-http.test.ts`

**Interfaces:**
- Produces: `loadOrCreateRelayIdentity(dataDir)`, `createSignedRelayDescriptor(identity, endpoint)`, `verifyRelayHello(response, nonce, expectedRelay?)`.
- Relay identity files are stored under the relay data directory and survive process restarts.

- [ ] **Step 1: Write failing persistence and nonce-binding tests**

Test that two loads from the same data directory return the same full `relayId`, that a different data directory produces a different relay ID, and that `POST /api/quantic/federation/hello` echoes the caller nonce and includes a verifiable P-256 signature.

- [ ] **Step 2: Run focused tests and confirm RED**

Run:

```bash
node --experimental-transform-types --test tests/relay-identity.test.ts tests/standalone-relay-federation-http.test.ts
```

Expected: FAIL because the relay identity/hello endpoint is absent.

- [ ] **Step 3: Implement relay identity**

Use Node `generateKeyPairSync("ec", { namedCurve: "prime256v1" })`, export public SPKI DER and private PKCS8 PEM/DER in a relay-owned state file with existing restrictive file permissions. Define:

```ts
export type RelayIdentity = {
  relayId: string;
  publicKeyJwk: JsonWebKey;
  privateKeyPem: string;
};
```

Compute `relayId` as lowercase hex SHA-256 of SPKI DER. Sign canonical descriptor/hello text with ECDSA SHA-256 and IEEE-P1363 encoding.

- [ ] **Step 4: Add hello endpoint and server wiring**

`POST /api/quantic/federation/hello` accepts `{ nonce: string }`, rejects nonce outside 16..256 printable/base64url characters, and returns descriptor + signature. The server must know its public endpoint from `QUANTIC_RELAY_PUBLIC_ENDPOINT` or a normalized local listen URL in tests.

- [ ] **Step 5: Run tests and full suite**

Run:

```bash
node --experimental-transform-types --test tests/relay-identity.test.ts tests/standalone-relay-federation-http.test.ts
npm test
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add standalone-relay/identity.ts standalone-relay/server.ts standalone-relay/http.ts standalone-relay/storage.ts tests/relay-identity.test.ts tests/standalone-relay-federation-http.test.ts
git commit -m "feat: add persistent relay federation identity"
```

---

### Task 3: Signed Route Manifest state with rollback/fork protection

**Files:**
- Create: `lib/quantic/route-manifest-node.mjs`
- Create: `lib/quantic/route-manifest-state.ts`
- Modify: `lib/quantic/relay-state.ts`
- Test: `tests/route-manifest.test.mjs`
- Test: `tests/relay-state.test.ts`

**Interfaces:**
- Produces: `assertVerifiedRouteManifest(manifest, identityManifest, cryptoProfile?)`, `acceptRouteManifest(manifest, context)`, `getRouteManifest(canonicalAddress)`.
- Relay persistent snapshot gains `routeManifests` without altering existing V1.1 identity/prekey state.

- [ ] **Step 1: Write failing signature/rollback/fork tests**

Generate a P-256 identity signing key in the test, sign `canonicalRouteManifestText(payload)`, then verify: valid sequence accepted; lower sequence rejected; same sequence/different payload rejected; expired manifest rejected for routing; endpoint key and `relayId` must match.

- [ ] **Step 2: Run tests and confirm RED**

Run: `node --test tests/route-manifest.test.mjs`

Expected: FAIL because verifier/state do not exist.

- [ ] **Step 3: Implement Node verification and monotonic state**

Use existing identity manifest verification rules to bind `canonicalAddress` and `identitySigningPublicKey`. Require the route `identityManifestSequence` not to claim a future identity sequence unavailable to the verifier. Store only the highest valid route sequence per canonical identity.

- [ ] **Step 4: Extend durable relay snapshot**

Add a version-compatible optional `routeManifests` record to `RelayPersistentState`. Restore older snapshots by defaulting it to empty. Keep atomic persistence behavior unchanged.

- [ ] **Step 5: Run focused and full tests**

```bash
node --test tests/route-manifest.test.mjs
node --experimental-transform-types --test tests/relay-state.test.ts
npm test
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add lib/quantic/route-manifest-node.mjs lib/quantic/route-manifest-state.ts lib/quantic/relay-state.ts tests/route-manifest.test.mjs tests/relay-state.test.ts
git commit -m "feat: persist signed Quantic route manifests"
```

---

### Task 4: Portable device signature and destination relay ingress

**Files:**
- Create: `lib/quantic/federation-node.mjs`
- Modify: `lib/quantic/relay.ts`
- Modify: `standalone-relay/http.ts`
- Test: `tests/federation-envelope.test.mjs`
- Test: `tests/standalone-relay-federation-http.test.ts`

**Interfaces:**
- Produces: `verifyPortableEnvelope(envelope, senderManifest, senderCryptoProfile?)`, `enqueueFederatedEnvelope(packet)`.
- `enqueueFederatedEnvelope` never accepts an auth token and only stores after sender proof + recipient authorization verification.

- [ ] **Step 1: Write failing sender-proof tests**

Create an identity manifest with a linked device signing public key. Sign `canonicalPortableEnvelopeText(envelope)` using that device private key. Assert valid signature passes; changed recipient/ciphertext/expiry fails; revoked/unknown device fails.

- [ ] **Step 2: Confirm RED**

Run: `node --test tests/federation-envelope.test.mjs`

Expected: FAIL because verifier is absent.

- [ ] **Step 3: Implement verification and federated queue insertion**

Use Node `verify("sha256", ...)` with the manifest device signing key. On successful verification, insert the opaque envelope into the recipient device queue using a dedicated path that does not call `authenticateDevice`. Preserve idempotency on `(from, fromDeviceId, clientMessageId)`.

- [ ] **Step 4: Expose destination ingress endpoint**

Implement `POST /api/quantic/federation/forward`. Initially require that the receiving relay itself appears in the recipient Route Manifest. Validate packet expiry, `hopLimit > 0`, no self in `visitedRelayIds`, route sequence, destination relay identity, sender/recipient signed records, sender envelope signature and replay state.

- [ ] **Step 5: Run focused/full tests**

```bash
node --test tests/federation-envelope.test.mjs
node --experimental-transform-types --test tests/standalone-relay-federation-http.test.ts
npm test
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add lib/quantic/federation-node.mjs lib/quantic/relay.ts standalone-relay/http.ts tests/federation-envelope.test.mjs tests/standalone-relay-federation-http.test.ts
git commit -m "feat: accept portable federated envelopes"
```

---

### Task 5: Origin forwarding client, replay state and signed federation receipts

**Files:**
- Create: `standalone-relay/federation-client.ts`
- Create: `standalone-relay/federation-state.ts`
- Modify: `lib/quantic/relay-state.ts`
- Modify: `lib/quantic/relay.ts`
- Modify: `standalone-relay/http.ts`
- Test: `tests/federation-receipt.test.ts`
- Test: `tests/standalone-relay-restart.test.ts`

**Interfaces:**
- Produces: `forwardToRoute(packet, route, options)`, durable seen-federation state, pending outbound federation records and pending federation receipts.
- A verified remote receipt is translated into the existing sender receipt queue.

- [ ] **Step 1: Write failing receipt and replay tests**

Test that exact retry of one federation ID/envelope digest is idempotent, same federation ID with a different digest is rejected, Bob ACK causes a destination-relay-signed federation receipt, and the origin converts a verified receipt into Alice's normal receipt queue.

- [ ] **Step 2: Confirm RED**

Run: `node --experimental-transform-types --test tests/federation-receipt.test.ts`

Expected: FAIL because forwarding/receipt state is absent.

- [ ] **Step 3: Implement durable federation state**

Persist:

```ts
type FederationSeenRecord = { federationId: string; envelopeDigest: string; expiresAt: string; result: "accepted" | "delivered" };
type PendingFederationReceipt = { receipt: QuanticFederationReceipt; originEndpoint: string; nextAttemptAt: string; attempts: number };
```

Prune by expiry on restore/mutation. Never store user bearer tokens in these records.

- [ ] **Step 4: Implement forwarding and receipt endpoint**

Origin performs `/federation/hello`, pins the route relay identity, posts `/federation/forward`, and records the route sequence used. Destination signs a receipt only after the existing recipient ACK removes the queued envelope. `POST /api/quantic/federation/receipt` verifies relay signature + stored route authorization before creating Alice's normal delivery receipt.

- [ ] **Step 5: Verify restart durability**

Extend restart tests so pending replay state and pending receipts survive a relay restart without duplicate queue insertion.

- [ ] **Step 6: Run full tests**

```bash
npm test
npm run build
npm run lint
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add standalone-relay/federation-client.ts standalone-relay/federation-state.ts lib/quantic/relay-state.ts lib/quantic/relay.ts standalone-relay/http.ts tests/federation-receipt.test.ts tests/standalone-relay-restart.test.ts
git commit -m "feat: add durable federation forwarding and receipts"
```

---

### Task 6: Two-relay end-to-end acceptance test and protocol documentation

**Files:**
- Create: `tests/standalone-relay-federation-e2e.test.ts`
- Modify: `docs/quantic-relay-v1.md`
- Modify: `docs/quantic-relay-standalone.md`
- Modify: `.github/workflows/ci.yml`

**Interfaces:**
- Produces the Federation V1 acceptance proof consumed by later Crypto V2 and Discovery Mesh work.

- [ ] **Step 1: Write the failing two-relay acceptance test**

The test starts standalone relay A and B with separate temp data directories. It registers Alice only on A and Bob only on B, publishes/verifies Bob's signed Route Manifest on A, sends a portable P-256-signed encrypted envelope through A→B, has Bob pull/decrypt/ACK from B, delivers the federation receipt B→A, and confirms Alice reads the normal receipt from A. No GitHub registry configuration is present.

- [ ] **Step 2: Confirm RED before final integration changes**

Run: `node --experimental-transform-types --test tests/standalone-relay-federation-e2e.test.ts`

Expected: FAIL until all wiring is complete.

- [ ] **Step 3: Complete only the missing wiring revealed by the acceptance test**

No new protocol behavior is introduced in this step. Fix only integration gaps between Tasks 1–5.

- [ ] **Step 4: Add CI federation smoke**

Ensure the normal `npm test` suite includes the E2E test and keep existing standalone CLI smoke/build/lint jobs intact.

- [ ] **Step 5: Document exact non-claims**

Document that Federation V1 supports direct relay A→B routing from already-known signed routes. Automatic unknown-recipient discovery/DHT and post-quantum enforcement are explicitly deferred to their separate plans.

- [ ] **Step 6: Final verification**

```bash
npm install
npm test
npm run build
npm run lint
```

Expected: all green.

- [ ] **Step 7: Commit**

```bash
git add tests/standalone-relay-federation-e2e.test.ts docs/quantic-relay-v1.md docs/quantic-relay-standalone.md .github/workflows/ci.yml
git commit -m "test: prove direct Quantic relay federation"
```
