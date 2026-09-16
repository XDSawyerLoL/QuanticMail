# QuanticMail V1.0 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship a tested V1.0 protocol with signed identity manifests, anti-rollback protection, device revocation, and an optional durable GitHub registry checkpoint while preserving zero-cost memory-only operation.

**Architecture:** Render remains the transient message relay. A root-signed identity manifest becomes the authority for active devices and revocations; clients cache the highest sequence they have observed. An optional GitHub registry adapter checkpoints signed manifests durably without becoming part of the realtime message path.

**Tech Stack:** Next.js 16.3.3, React 19.2, TypeScript 5.9, Node.js built-in test runner, Web Crypto / Node crypto, IndexedDB, Render, GitHub REST Contents API.

**Spec:** `docs/superpowers/specs/2026-09-16-quanticmail-v1-design.md`

## Global Constraints

- No paid infrastructure is required.
- Root private signing keys never leave the root device except in an explicitly exported encrypted Identity Vault.
- Linked devices keep independent private keys.
- Render never receives message plaintext.
- GitHub registry support is optional and disabled safely when credentials are absent.
- Existing V0.9 addresses and pairing remain compatible.

---

### Task 1: Add protocol test harness and RED manifest tests

**Files:**
- Modify: `package.json`
- Modify: `.github/workflows/ci.yml`
- Create: `tests/manifest-core.test.mjs`
- Create later in GREEN: `lib/quantic/manifest-core.mjs`

**Interfaces:**
- Produces `canonicalManifestText(payload)`, `validateManifestShape(manifest)`, `activeDevices(manifest)`, `mergeManifestState(current, incoming)`.

- [ ] Add `npm test` using `node --test tests/*.test.mjs`.
- [ ] Add CI `npm test` before build.
- [ ] Write failing tests for deterministic serialization, exactly one root, revoked-device exclusion, and sequence rollback.
- [ ] Confirm CI fails because `manifest-core.mjs` does not exist.
- [ ] Implement minimal pure-JS protocol core.
- [ ] Confirm tests pass.

### Task 2: Add signed manifest crypto

**Files:**
- Create: `lib/quantic/manifest.ts`
- Modify: `lib/quantic/crypto.ts`
- Add tests: `tests/manifest-signature.test.mjs` using Node crypto-compatible fixtures/core helpers.

**Interfaces:**
- Produces `createInitialManifest(identity)`, `signManifest(identity, payload)`, `verifyManifest(manifest)`, `nextManifestWithDevice(...)`, `nextManifestWithoutDevice(...)`.

- [ ] Write failing signature/fingerprint tests.
- [ ] Verify RED.
- [ ] Implement deterministic signing and verification using ECDSA P-256/SHA-256.
- [ ] Verify GREEN.

### Task 3: Persist anti-rollback state locally

**Files:**
- Modify: `lib/quantic/local-db.ts`

**Interfaces:**
- Extend `LocalContact` with `manifestSequence` and `signingPublicKey`.
- Add local identity `manifest?: QuanticIdentityManifest`.

- [ ] Add tests to the pure manifest core for sequence rules.
- [ ] Migrate IndexedDB version and local types.
- [ ] Preserve V0.9 data during upgrade.

### Task 4: Make relay derive authorization from manifests

**Files:**
- Modify: `lib/quantic/relay.ts`
- Create: `app/api/quantic/manifest/route.ts`
- Modify: `app/api/quantic/register/route.ts`
- Modify: `app/api/quantic/devices/register/route.ts`
- Modify: `app/api/quantic/resolve/route.ts`

**Interfaces:**
- Relay exposes verified manifest load/publish.
- Resolve returns `manifest` and active devices.
- Authentication rejects device IDs absent from latest manifest.

- [ ] Write failing pure-core tests for stale device reactivation.
- [ ] Verify RED.
- [ ] Implement manifest cache/validation and route.
- [ ] Verify tests/build.

### Task 5: Implement root-signed revocation

**Files:**
- Create: `app/api/quantic/devices/revoke/route.ts`
- Modify: `components/devices-app.tsx`
- Modify: `app/quantic.css`

**Interfaces:**
- Root client signs sequence N+1 manifest removing target device and adding revocation record.
- Server validates/publishes the full signed manifest.

- [ ] Write failing revocation test in `manifest-core.test.mjs`.
- [ ] Verify RED.
- [ ] Implement client revocation manifest creation.
- [ ] Add UI action only for linked devices and only on root device.
- [ ] Verify GREEN/build/lint.

### Task 6: Route sends using latest manifest

**Files:**
- Modify: `components/quantic-network-app.tsx`
- Modify: `lib/quantic/local-db.ts`

**Interfaces:**
- Contact trust pins root signing key + max manifest sequence.
- Device encryption keys are allowed to evolve under a valid later manifest.

- [ ] Add rollback/contact trust tests to pure core.
- [ ] Verify RED.
- [ ] Resolve and verify manifest before fan-out.
- [ ] Reject lower sequence than local contact state.
- [ ] Persist latest sequence/signing key.
- [ ] Verify GREEN/build/lint.

### Task 7: Add optional GitHub durable registry

**Files:**
- Create: `lib/quantic/registry-store.ts`
- Create: `app/api/quantic/registry/status/route.ts`
- Modify: `lib/quantic/relay.ts`
- Create: `tests/registry-path.test.mjs`

**Interfaces:**
- `getRegistryStore()` returns memory-only behavior when credentials are absent.
- GitHub adapter stores signed manifests at `registry/identities/<sha256(canonicalAddress)>.json`.

- [ ] Write failing deterministic path tests.
- [ ] Verify RED.
- [ ] Implement GitHub Contents API read/write with optimistic SHA update.
- [ ] Never expose token to client responses.
- [ ] Make failures degrade to memory mode for realtime transport while reporting checkpoint status.
- [ ] Verify GREEN/build/lint.

### Task 8: Documentation and production verification

**Files:**
- Modify: `README.md`
- Create: `docs/V1.0-PROTOCOL.md`

- [ ] Document guarantees, degraded memory-only mode, GitHub checkpoint variables, and security limits.
- [ ] Run complete CI: tests → build → lint → deployment validations.
- [ ] Open PR to `main`.
- [ ] Merge only if CI is green.
- [ ] Confirm Render deploy is `live` and routes `/devices`, `/vault`, `/api/quantic/manifest`, `/api/quantic/registry/status` are built.
