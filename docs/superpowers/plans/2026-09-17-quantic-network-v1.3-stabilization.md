# Quantic Network V1.3 Stabilization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stabilize Quantic Network V1.3 with Discovery-first short-handle resolution, multiple bootstraps, hardened relay persistence, opportunistic direct transport and reusable Quantic Core app capabilities.

**Architecture:** Preserve the existing signed-manifest / Federation / Crypto V2 stack and add only bounded seams around it. The same signed Discovery bundle is indexed under canonical and short-handle keys; relay hardening is additive; direct transport carries the existing encrypted envelope unchanged and falls back to relay delivery; Quantic Core app capabilities are root-signed but use separate app keys.

**Tech Stack:** Next.js 16.3.3, React 19.2, TypeScript 5.9, Node 24.8, Web Crypto, WebRTC DataChannel, PostgreSQL, existing Quantic P-256 + ML-KEM-768 + ML-DSA-65 stack.

**Spec:** `docs/superpowers/specs/2026-09-17-quantic-network-v1.3-stabilization-design.md`

## Global Constraints

- Never persist readable message bodies or user private identity/device/PQ keys on relays.
- Preserve existing `hybrid-required` Crypto V2 anti-downgrade behavior.
- Short handles must fail with 409 when ambiguous.
- Direct transport must always fall back to store-and-forward.
- Remote relay endpoints require HTTPS; localhost may use HTTP.
- Existing V1.2 and legacy 10-hex identities remain compatible.

---

### Task 1: Discovery handle index and ambiguity-safe lookup

**Files:**
- Modify: `lib/quantic/discovery-core.mjs`
- Modify: `standalone-relay/kademlia.ts`
- Modify: `standalone-relay/discovery-service.ts`
- Modify: `standalone-relay/discovery-http.ts`
- Modify: `standalone-relay/http.ts`
- Test: `tests/discovery-handle-resolution.test.ts`

**Interfaces:**
- Produces `normalizeDiscoveryHandle(value)`, `discoveryHandleKey(handle)`.
- Produces `DiscoveryService.lookupHandle(handle)` returning `{ status: "not-found" | "unique" | "ambiguous", bundle?, canonicalAddresses? }`.
- `iterativeFindRecord` gains optional `collectAllRecords` and returns `records` without changing default early-return behavior.

- [ ] Write tests showing a unique signed bundle resolves by short handle after live identity state is cleared and two different valid canonical identities with the same handle produce ambiguity.
- [ ] Run the targeted test on the branch and confirm RED.
- [ ] Implement handle-key derivation, local handle indexing, bounded multi-path record collection and `lookupHandle` validation using the existing bundle verifier.
- [ ] Route standalone `/api/quantic/resolve` through Discovery handle lookup only after local resolution returns 404.
- [ ] Verify malformed, wrong-handle and downgrade bundles are ignored/rejected and ambiguity returns HTTP 409.

### Task 2: Quantic Network public facade and Quantic Core capability primitives

**Files:**
- Create: `lib/quantic-network/addressing.mjs`
- Create: `lib/quantic-network/index.ts`
- Create: `lib/quantic-core/app-capability-core.mjs`
- Create: `lib/quantic-core/app-capability.ts`
- Test: `tests/app-capability.test.ts`

**Interfaces:**
- `normalizeQuanticLocator(value)` and `isCanonicalQuanticAddress(value)` become stable product-neutral helpers.
- `createAppCapability(identity, app, appSigningPublicKey, scopes, expiresAt)` returns a root-signed `quantic-app-capability`.
- `verifyAppCapability(capability, manifest, nowMs?)` verifies root continuity, signature, expiry and app/scopes structure.

- [ ] Write RED tests for valid capability, tampered app key, wrong canonical identity and expiry.
- [ ] Implement deterministic capability canonicalization and browser signing/verification using existing Quantic signing helpers.
- [ ] Add a product-neutral facade without deleting existing `lib/quantic/*` compatibility imports.
- [ ] Run capability tests and existing manifest tests.

### Task 3: Multi-bootstrap client defaults

**Files:**
- Modify: `lib/quantic/relay-client.ts`
- Test: `tests/relay-client.test.ts`
- Test: `tests/durable-bootstrap-client.test.ts`

**Interfaces:**
- `parseDefaultRelayEndpoints(value?: string)` parses `NEXT_PUBLIC_QUANTIC_BOOTSTRAPS`-style comma separated seeds.
- `mergeDefaultRelayEndpoints(configured, builtIns)` normalizes and deduplicates by base URL.

- [ ] Add RED tests for multiple HTTPS seeds, duplicate origins, invalid remote HTTP and preservation of same-origin fallback.
- [ ] Implement parser/merger and migrate saved legacy configuration without deleting user-added relays.
- [ ] Keep current hosted durable relay as one compatibility seed, not the sole default authority.
- [ ] Run relay-client tests.

### Task 4: PostgreSQL concurrency and encrypted relay identity

**Files:**
- Modify: `standalone-relay/postgres-storage.ts`
- Modify: `standalone-relay/main.ts`
- Modify: `standalone-relay/server.ts`
- Modify: `.env.example`
- Test: `tests/postgres-relay-storage.test.ts`

**Interfaces:**
- PostgreSQL KV rows gain `revision BIGINT NOT NULL DEFAULT 0`.
- State store rejects stale `save` operations with `RelayStateConflictError`.
- `createPostgresRelayPersistenceFromUrl(url, { identitySecret? })` encrypts relay identity when a secret is present.

- [ ] Add RED tests for stale revision conflict and encrypted-identity round trip/wrong-secret rejection using the existing query-client test double.
- [ ] Implement optimistic revision SQL and revision tracking.
- [ ] Implement scrypt + AES-256-GCM identity-at-rest format with backward-compatible plaintext migration.
- [ ] Wire `QUANTIC_RELAY_IDENTITY_SECRET` through CLI/server options and document it.
- [ ] Run storage tests.

### Task 5: Standalone relay HTTP hardening and authenticated direct signaling

**Files:**
- Create: `standalone-relay/direct-signaling.ts`
- Modify: `standalone-relay/http.ts`
- Modify: `standalone-relay/server.ts`
- Test: `tests/direct-signaling.test.ts`

**Interfaces:**
- Direct signaling routes: `/api/quantic/direct/announce`, `/api/quantic/direct/send`, `/api/quantic/direct/poll`.
- Signaling messages are opaque JSON payloads with strict type, byte, queue and TTL bounds and are scoped to authenticated canonical identity/device pairs.

- [ ] Write RED tests for unauthenticated access, cross-device polling, TTL expiry and queue bounding.
- [ ] Implement in-memory opportunistic signaling store; do not persist SDP/ICE state.
- [ ] Authenticate every operation through existing relay device authentication.
- [ ] Configure Node HTTP request/header/keep-alive timeouts and max requests per socket.
- [ ] Run direct-signaling and standalone HTTP tests.

### Task 6: Browser WebRTC direct transport with relay fallback

**Files:**
- Create: `lib/quantic-network/direct-wire.mjs`
- Create: `lib/quantic-network/direct-transport.ts`
- Modify: `instrumentation-client.ts`
- Test: `tests/direct-wire.test.mjs`
- Test: `tests/direct-transport-policy.test.mjs`

**Interfaces:**
- Direct wire frames support `hello`, `envelope`, and `receipt` records; envelope frames reuse current ciphertext/IV/ephemeral key fields and never contain plaintext body/subject fields.
- `tryDirectSend()` returns `delivered-direct` only after peer acceptance; otherwise it returns `fallback` and normal relay fetch proceeds.
- Direct inbox/receipt queues are merged transparently into intercepted `/pull`, `/ack`, `/receipts` browser requests.

- [ ] Add RED protocol/policy tests proving encrypted-envelope-only frames and deterministic fallback.
- [ ] Implement WebRTC DataChannel coordinator with short connect timeout, relay-assisted signaling and authenticated app-level peer hello.
- [ ] Integrate only through the fetch instrumentation layer so QuanticMail outbox semantics remain unchanged.
- [ ] Confirm unsupported WebRTC or any connection/signaling error falls through to normal relay delivery.
- [ ] Run direct transport policy tests and production build.

### Task 7: Documentation, issue state and compatibility cleanup

**Files:**
- Modify: `README.md`
- Create: `docs/QUANTIC-NETWORK-V1.3.md`
- Modify: `package.json`

**Interfaces:**
- Version becomes `1.3.0` only after implementation tests pass.

- [ ] Document Discovery handle semantics, multi-bootstrap, encrypted relay identity, direct transport fallback and app capabilities.
- [ ] Mark SMTP/Stalwart work explicitly as legacy interoperability work rather than a Quantic Network requirement.
- [ ] Update issue #11 with implemented/deferred status after CI passes; close issue #5 only if its stated objective is no longer part of the active Quantic Network roadmap.

### Task 8: Full verification and PR

**Files:**
- Verify all changed files.

- [ ] Run `npm test` in GitHub Actions and require 0 failures.
- [ ] Run `npm run build` in GitHub Actions and require exit 0.
- [ ] Run `npm run lint` in GitHub Actions and require exit 0.
- [ ] Require standalone relay smoke test success.
- [ ] Inspect the final PR diff for plaintext key/message regressions and accidental secret material.
- [ ] Open a PR to `main` only after the full branch CI is green; do not auto-merge until final verification of the head SHA.
