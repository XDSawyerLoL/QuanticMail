# Quantic Discovery Mesh Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let standalone Quantic relays discover signed Identity Manifest + Crypto Profile + Route Manifest bundles without requiring GitHub or one central directory.

**Architecture:** Add a relay-only Kademlia-style discovery mesh with signed mutable records, durable peer tables, multiple independent lookup paths, record sequence/fork protection and configurable bootstrap peers. Browsers remain simple clients of their chosen relays.

**Tech Stack:** Node.js 24+, TypeScript, native TCP/HTTP transport initially, existing signed manifest validators, node:test.

**Spec:** `docs/superpowers/specs/2026-09-16-quantic-network-federation-discovery-pqc-design.md`

## Global Constraints

- Bootstrap nodes are entry points, never identity authorities.
- A discovered object is trusted only after its existing cryptographic validation succeeds.
- Cache rollback/forks are rejected; network partitions do not imply global consensus.
- Do not replicate the full Quantic directory to every relay.
- Queries use multiple independent paths to reduce simple Eclipse/Sybil influence.
- Render/GitHub are not required once relays know reachable peers and records.

---

### Task 1: Discovery record keys and signed bundle validation

**Files:** Create `lib/quantic/discovery-core.mjs`, `.d.mts`; Test `tests/discovery-core.test.mjs`.

**Interfaces:** `discoveryKey(kind, canonicalAddress)`, `validateDiscoveryBundle(bundle, pinnedState)`, `selectNewestValidRecord(records)`.

- [ ] Write failing deterministic-key and rollback/fork tests.
- [ ] Confirm RED.
- [ ] Implement SHA-256 namespaced keys for identity/crypto/route records and cross-record sequence/digest validation.
- [ ] Run tests and commit `feat: define Quantic discovery records`.

### Task 2: Durable peer table and node identity

**Files:** Create `standalone-relay/discovery-state.ts`; Modify `lib/quantic/relay-state.ts`; Test `tests/discovery-state.test.ts`.

**Interfaces:** durable peers with `relayId`, endpoint, lastSeenAt, failures, bucket distance metadata; restore/prune behavior.

- [ ] Write failing restart/prune tests.
- [ ] Confirm RED.
- [ ] Implement peer table persisted in the existing atomic relay snapshot.
- [ ] Run tests and commit `feat: persist Quantic discovery peers`.

### Task 3: Kademlia routing table and iterative lookup

**Files:** Create `standalone-relay/kademlia.ts`; Test `tests/kademlia.test.ts`.

**Interfaces:** `xorDistance(a,b)`, `KBucketTable`, `iterativeFindRecord(key, queryPeer, options)`.

- [ ] Write failing XOR-distance, bucket-capacity, nearest-peer and convergence tests.
- [ ] Confirm RED.
- [ ] Implement fixed-size buckets, LRU-style healthy peer retention and bounded iterative lookup.
- [ ] Default lookup uses three independent seeds/paths when enough peers exist.
- [ ] Run tests and commit `feat: add Quantic Kademlia routing core`.

### Task 4: Discovery HTTP protocol

**Files:** Modify `standalone-relay/http.ts`; Create `standalone-relay/discovery-http.ts`; Test `tests/discovery-http.test.ts`.

**Interfaces:** `POST /api/quantic/discovery/find`, `POST /api/quantic/discovery/publish`, `GET /api/quantic/discovery/peers` for diagnostics.

- [ ] Write failing endpoint tests for signed record publish, invalid signature rejection, nearest-peer fallback and response size limits.
- [ ] Confirm RED.
- [ ] Implement endpoints; never accept an unsigned/invalid bundle into trusted cache.
- [ ] Run tests and commit `feat: expose Quantic discovery protocol`.

### Task 5: Replication and cache convergence

**Files:** Create `standalone-relay/discovery-service.ts`; Test `tests/discovery-convergence.test.ts`.

**Interfaces:** publish valid records to the K closest known relay IDs; lookup caches newer valid records locally and ignores older/forked versions.

- [ ] Write failing 5-node convergence test.
- [ ] Confirm RED.
- [ ] Implement targeted replication and cache refresh; no broadcast gossip.
- [ ] Test partition/rejoin where newer route wins only after cryptographic/sequence validation.
- [ ] Run tests and commit `feat: replicate signed Quantic discovery records`.

### Task 6: Bootstrap configuration and no-central-service acceptance test

**Files:** Modify `standalone-relay/main.ts`, `standalone-relay/server.ts`, docs and CI; Create `tests/quantic-network-offline-central-e2e.test.ts`.

**Interfaces:** `QUANTIC_RELAY_BOOTSTRAP` accepts comma-separated relay endpoints; empty value is valid for isolated/private meshes.

- [ ] Write failing acceptance test with relays A/B/C, no GitHub token and no Render endpoint. B publishes Bob records, A starts knowing only C, A discovers Bob through the mesh and federates a message to B, Bob ACKs, Alice receives receipt.
- [ ] Confirm RED.
- [ ] Add bootstrap parsing, startup peer handshakes and record publication/lookup wiring.
- [ ] Run `npm test`, `npm run build`, `npm run lint`.
- [ ] Document bootstrap ≠ authority and private-network operation.
- [ ] Commit `test: prove Quantic discovery without central registry`.
