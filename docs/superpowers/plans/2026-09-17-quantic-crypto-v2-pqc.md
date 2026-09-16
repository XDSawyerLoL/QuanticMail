# Quantic Crypto V2 PQC Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an optional, downgrade-resistant hybrid post-quantum cryptographic profile using P-256 + ML-KEM-768 + ML-DSA-65 without changing existing Quantic canonical addresses.

**Architecture:** Keep Identity Manifest V1 unchanged. Add a separately signed Crypto Profile V2, per-device PQ public keys, hybrid envelope encryption using ECDH P-256 and ML-KEM-768 combined through HKDF-SHA-256, and dual P-256/ML-DSA signatures when policy becomes `hybrid-required`.

**Tech Stack:** Node.js 24.7+ native crypto/WebCrypto when available, browser capability detection, TypeScript, node:test.

**Spec:** `docs/superpowers/specs/2026-09-16-quantic-network-federation-discovery-pqc-design.md`

## Global Constraints

- Do not alter canonical Quantic addresses or Identity Manifest V1 wire format.
- Use platform/runtime PQ primitives only; no handwritten lattice cryptography.
- Initial suite is `QNT-HYB-P256-MLKEM768-HKDFSHA256-AES256GCM-1`.
- Once `hybrid-required` is pinned, silent downgrade to V1/classical-only delivery is forbidden.
- Preserve V1.1 one-time prekey semantics for classical compatibility.

---

### Task 1: Runtime PQ capability adapter

**Files:** Create `lib/quantic/pqc-runtime.ts`, `lib/quantic/pqc-runtime-node.ts`; Test `tests/pqc-runtime.test.ts`.

**Interfaces:** `detectPqcCapabilities()`, `generateMlKem768KeyPair()`, `generateMlDsa65KeyPair()`, `mlKemEncapsulate()`, `mlKemDecapsulate()`, `mlDsaSign()`, `mlDsaVerify()`.

- [ ] Write failing capability/round-trip tests that skip only when the runtime genuinely lacks the primitive.
- [ ] Run focused test and confirm RED because adapter is absent.
- [ ] Implement thin adapters over native runtime APIs with explicit algorithm names and SPKI/PKCS8 encoding.
- [ ] Run focused tests and `npm test`; expect PASS.
- [ ] Commit `feat: add native Quantic PQ crypto adapter`.

### Task 2: Crypto Profile V2 canonicalization and continuity

**Files:** Create `lib/quantic/crypto-profile-core.mjs`, `.d.mts`, `lib/quantic/crypto-profile-node.mjs`, `lib/quantic/crypto-profile-state.ts`; Test `tests/crypto-profile.test.mjs`.

**Interfaces:** `canonicalCryptoProfileText(payload)`, `verifyCryptoProfile(profile, identityManifest, previousProfile)`, `acceptCryptoProfile(profile)`.

- [ ] Write failing tests for first activation P-256 + ML-DSA self-signature, sequence rollback, same-sequence fork, continuity signature on updates, and key rotation signed by old+new ML-DSA keys.
- [ ] Confirm RED.
- [ ] Implement strict canonicalization, verification and monotonic state.
- [ ] Add durable profile state to standalone relay snapshots with backward-compatible restore.
- [ ] Run focused/full tests; expect PASS.
- [ ] Commit `feat: add Quantic Crypto Profile V2`.

### Task 3: Per-device PQ keys and local storage

**Files:** Modify `lib/quantic/local-db.ts`, `lib/quantic/device.ts`; Create `lib/quantic/device-pqc.ts`; Test `tests/device-pqc.test.ts`.

**Interfaces:** each active device stores local ML-KEM private/public and ML-DSA private/public material; only public material enters Crypto Profile V2.

- [ ] Write failing tests that a linked device proves proposed PQ keys with its existing P-256 signing key plus ML-DSA self-signature.
- [ ] Confirm RED.
- [ ] Implement generation/storage/request verification and root approval path.
- [ ] Verify private PQ material never appears in serialized public profile.
- [ ] Run tests and commit `feat: add per-device Quantic PQ keys`.

### Task 4: Hybrid secret combination and envelope V2

**Files:** Create `lib/quantic/hybrid-crypto.ts`; Modify `lib/quantic/envelope-core.mjs`, `lib/quantic/envelope-crypto.mjs`, `lib/quantic/federation-core.mjs`; Test `tests/hybrid-envelope.test.ts`.

**Interfaces:** `deriveHybridAesKey(classicalSecret, pqSecret, context)`, `encryptHybridEnvelope()`, `decryptHybridEnvelope()`.

- [ ] Write failing round-trip/tamper/context-binding tests.
- [ ] Confirm RED.
- [ ] Combine exactly 32-byte ECDH secret and ML-KEM shared secret via HKDF-SHA-256 with context including suite/from/fromDevice/to/toDevice/clientMessageId.
- [ ] Encrypt/decrypt with AES-256-GCM; carry ML-KEM ciphertext and classical ephemeral public key in the portable envelope.
- [ ] Run tests and commit `feat: add hybrid Quantic envelope encryption`.

### Task 5: Anti-downgrade policy enforcement

**Files:** Modify `lib/quantic/federation-node.mjs`, client send path, route/profile validators; Test `tests/pqc-downgrade.test.mjs`.

**Interfaces:** `resolveCryptoPolicy(identity, pinnedProfile)` and enforcement in send/receive/federation verification.

- [ ] Write failing tests: never-upgraded identity may receive V1; `transition` permits V1 with explicit capability result; pinned `hybrid-required` rejects missing PQ signature/KEM/profile; stale profile cannot erase required policy.
- [ ] Confirm RED.
- [ ] Implement policy state and clear user-facing incompatibility error instead of silent downgrade.
- [ ] Run full tests/build/lint and commit `feat: enforce Quantic PQ anti-downgrade policy`.

### Task 6: Crypto V2 acceptance test and docs

**Files:** Create `tests/crypto-v2-e2e.test.ts`; Modify security docs/CI.

- [ ] Write end-to-end test for Alice/Bob hybrid send, relay transport, Bob decrypt, receipt; tamper one PQ field and assert rejection.
- [ ] Confirm RED until final wiring complete.
- [ ] Complete only missing integration wiring.
- [ ] Run `npm test`, `npm run build`, `npm run lint`.
- [ ] Document runtime capability limitations and non-claims.
- [ ] Commit `test: prove Quantic Crypto V2 hybrid delivery`.
