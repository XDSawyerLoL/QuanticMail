# QuanticMail V1.1 Secure Sync Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add strong new canonical IDs, one-time ECDH prekeys, QR rendezvous pairing with encrypted history bootstrap, ongoing sent-history sync, and activate the existing durable-registry path as far as available credentials permit.

**Architecture:** Preserve V1.0 manifests and existing 10-hex identities. Add focused client/server modules for prekeys and pairing instead of expanding relay.ts further. One-time prekeys are transiently published to Render but private keys remain in IndexedDB; QR pairing uses a 256-bit fragment secret and an ephemeral relay rendezvous; history is encrypted end-to-end inside the pairing package.

**Tech Stack:** Next.js 16.3.3, React 19.2, TypeScript 5.9, WebCrypto P-256 ECDH/ECDSA, AES-256-GCM, HKDF-SHA-256, IndexedDB, Node crypto, GitHub Contents API, Render.

**Spec:** `docs/superpowers/specs/2026-09-16-quanticmail-v1.1-secure-sync-design.md`

## Global Constraints

- Existing 10-hex canonical identities remain valid and MUST NOT be silently renamed.
- New identities use 32 hex characters (128 bits) in canonical addresses.
- Private identity, device and prekey keys remain client-side.
- One-time-prekey mode and static fallback are explicitly distinguishable.
- Pairing invites expire after 10 minutes and encrypted packages are capped at 4 MiB.
- Pairing QR secrets live in the URL fragment and are never placed in query parameters.
- No UI/documentation may claim Signal-equivalent security, full decentralization or complete forward secrecy.
- Release requires `npm test`, `npm run build`, `npm run lint`, deployment validations, merge, and Render `live` verification.

---

### Task 1: Strong canonical fingerprints with legacy compatibility

**Files:**
- Modify: `lib/quantic/crypto.ts`
- Modify: `lib/quantic/relay.ts`
- Modify: `components/quantic-network-v1-app.tsx`
- Modify: `lib/quantic/manifest-core.mjs`
- Test: `tests/strong-identity.test.mjs`

**Interfaces:**
- Produces: `fingerprintPublicKeyStrong(publicJwk): Promise<string>` returning exactly 32 lower-case hex chars.
- Relay canonical parser accepts fingerprints matching `(?:[0-9a-f]{10}|[0-9a-f]{32})`.
- Existing `fingerprintPublicKey()` stays 10-hex for legacy callers.

- [ ] **Step 1: Write failing identity compatibility tests**

```js
assert.equal(strongFingerprint.length, 32);
assert.match(strongFingerprint, /^[0-9a-f]{32}$/);
assert.equal(parseCanonicalForTest("alice~0123456789@quantic").fingerprint.length, 10);
assert.equal(parseCanonicalForTest("alice~0123456789abcdef0123456789abcdef@quantic").fingerprint.length, 32);
```

- [ ] **Step 2: Run `npm test` and verify the new tests fail because the strong helper/32-hex parser do not exist.**
- [ ] **Step 3: Add `fingerprintPublicKeyStrong()` using the existing canonical signing-key SHA-256 digest and `.slice(0, 32)`.**
- [ ] **Step 4: Update new-identity creation to use the strong helper while `ensureLocalIdentity()` preserves any stored canonical address/fingerprint.**
- [ ] **Step 5: Update server/manifest locator validation to accept exactly 10 or 32 hex characters.**
- [ ] **Step 6: Run `npm test`, `npm run build`, `npm run lint`; commit when green.**

### Task 2: Client prekey primitives and IndexedDB pool

**Files:**
- Create: `lib/quantic/prekey.ts`
- Modify: `lib/quantic/local-db.ts`
- Test: `tests/prekey-core.test.mjs`

**Interfaces:**
- Produces `SignedPreKeyRecord` with `version`, `canonicalAddress`, `deviceId`, `preKeyId`, `publicKey`, `createdAt`, `expiresAt`, `signature`.
- Produces `generateOneTimePreKey(identity)`, `verifyPreKeyBrowser(record, deviceSigningPublicKey)`, `canonicalPreKeyText(record)`.
- Local DB produces `saveLocalPreKeys(records)`, `getLocalPreKey(id)`, `listAvailableLocalPreKeys()`, `deleteLocalPreKey(id)`, `countAvailableLocalPreKeys()`.

- [ ] **Step 1: Write failing deterministic-text/signature/tamper/expiry tests.**
- [ ] **Step 2: Run tests and confirm RED.**
- [ ] **Step 3: Implement P-256 ECDH prekey generation plus ECDSA P-256/SHA-256 signature using the device signing key.**
- [ ] **Step 4: Increment IndexedDB from 5 to 6 and add `prekeys` keyed by `preKeyId`.**
- [ ] **Step 5: Implement batch save/list/get/delete/count operations, filtering expired records.**
- [ ] **Step 6: Run tests/build/lint; commit when green.**

### Task 3: Relay prekey publication and atomic claims

**Files:**
- Create: `lib/quantic/prekey-relay.ts`
- Create: `app/api/quantic/prekeys/publish/route.ts`
- Create: `app/api/quantic/prekeys/claim/route.ts`
- Create: `app/api/quantic/prekeys/status/route.ts`
- Modify: `lib/quantic/relay.ts` only to expose authenticated-device/public-device lookup helpers needed by the focused relay module.
- Test: `tests/prekey-relay.test.mjs`

**Interfaces:**
- `publishPreKeys(locator, authToken, deviceId, records)` accepts max 64 records and retains max 64 unexpired records/device.
- `claimPreKey(canonicalAddress, deviceId)` returns one valid signed record and removes it atomically.
- `preKeyStatus(locator, authToken, deviceId)` returns `{available:number}`.

- [ ] **Step 1: Write failing tests for publish, single claim, second-claim miss, expiry, invalid signature and revoked-device rejection.**
- [ ] **Step 2: Run tests and confirm RED.**
- [ ] **Step 3: Implement transient pools in a global relay state keyed by `canonicalAddress#deviceId`.**
- [ ] **Step 4: Validate each record against the authorized device-signing public key before storing or returning it.**
- [ ] **Step 5: Implement routes with 400/401/404/409 semantics and payload limits.**
- [ ] **Step 6: Run tests/build/lint; commit when green.**

### Task 4: Message encryption/decryption using claimed prekeys

**Files:**
- Modify: `lib/quantic/crypto.ts`
- Modify: `lib/quantic/local-db.ts`
- Modify: `lib/quantic/relay.ts`
- Modify: `app/api/quantic/send/route.ts`
- Modify: `components/quantic-network-v1-app.tsx`
- Test: `tests/prekey-envelope.test.mjs`

**Interfaces:**
- Envelope fields add `keyMode: "one-time-prekey" | "static-fallback"` and optional `preKeyId`.
- `encryptForRecipient()` continues to encrypt to any supplied P-256 ECDH public JWK.
- Receiver selects `localPreKey.privateKey` when `keyMode === "one-time-prekey"`, then deletes it only after successful authenticated decryption and local message persistence.

- [ ] **Step 1: Write failing tests proving one-time decryption succeeds, deletion prevents reuse, and static fallback still works.**
- [ ] **Step 2: Run tests and confirm RED.**
- [ ] **Step 3: Add envelope metadata through outbox, relay and send route.**
- [ ] **Step 4: Add `claimRecipientKey(canonicalAddress, device)` in the client: claim prekey, verify its signature, otherwise use device static key.**
- [ ] **Step 5: Add `ensurePreKeyPool(identity)` that replenishes local pool to 32 and publishes public records when fewer than 12 remain.**
- [ ] **Step 6: Decrypt with the matching local private prekey and delete after persistence; never acknowledge an undecryptable envelope.**
- [ ] **Step 7: Run tests/build/lint; commit when green.**

### Task 5: Ephemeral pairing rendezvous and encrypted package

**Files:**
- Create: `lib/quantic/pairing-crypto.ts`
- Create: `lib/quantic/pairing-relay.ts`
- Create: `app/api/quantic/pairing/invite/route.ts`
- Create: `app/api/quantic/pairing/request/route.ts`
- Create: `app/api/quantic/pairing/status/route.ts`
- Create: `app/api/quantic/pairing/package/route.ts`
- Test: `tests/pairing-core.test.mjs`

**Interfaces:**
- `createPairingInvite()` returns `{inviteId, secret, expiresAt}` client-side; server stores only SHA-256(secret).
- `derivePairingKey(secret, inviteId)` uses HKDF-SHA-256 and AES-256-GCM.
- Pairing package plaintext is `{certificate, manifest, history, partialHistory}`.

- [ ] **Step 1: Write failing tests for expiry, wrong secret, one-time pickup, AES-GCM roundtrip and tamper rejection.**
- [ ] **Step 2: Run tests and confirm RED.**
- [ ] **Step 3: Implement HKDF/AES-GCM client crypto with `quantic-pairing-v1:<inviteId>` info.**
- [ ] **Step 4: Implement 10-minute global-memory rendezvous state with secret-hash comparison and 4 MiB package limit.**
- [ ] **Step 5: Implement invite/request/status/package routes.**
- [ ] **Step 6: Run tests/build/lint; commit when green.**

### Task 6: QR pairing UI and history bootstrap

**Files:**
- Modify: `package.json` / `package-lock.json` to add `qrcode` and `@types/qrcode`.
- Modify: `components/devices-v1-app.tsx`
- Modify: `lib/quantic/local-db.ts`
- Modify: `app/quantic.css`

**Interfaces:**
- Root UI generates QR for `/devices?pair=<inviteId>#secret=<secret>` and a copyable fallback link.
- New-device UI auto-detects query+fragment, creates pending device keys, submits public request and polls package.
- `importLocalMessages(messages)` writes by message ID and returns `{imported, existing}`.

- [ ] **Step 1: Add `qrcode` dependency and render QR data URLs locally; no external QR service.**
- [ ] **Step 2: Root creates invite, displays expiry and polls for a public device request.**
- [ ] **Step 3: Root approval reuses `createDeviceCertificate()` + `addDeviceToManifest()`, builds newest-first history snapshot, trims until encrypted package is <=4 MiB, encrypts and posts package.**
- [ ] **Step 4: New device reads fragment secret, installs/decrypts package, validates cert+manifest, imports history idempotently and redirects to `/`.**
- [ ] **Step 5: Keep existing file pairing forms as fallback under an advanced section.**
- [ ] **Step 6: Run tests/build/lint; commit when green.**

### Task 7: Ongoing sent-history sync copies

**Files:**
- Modify: `components/quantic-network-v1-app.tsx`
- Modify: `lib/quantic/local-db.ts`
- Test: `tests/history-sync.test.mjs`

**Interfaces:**
- Plain payload adds `syncCopy?: boolean` and stable logical message `id`.
- After external send, create encrypted self-deliveries to all other active devices in the sender manifest.
- Receiver persists `syncCopy` as `direction: "out"`; normal deliveries remain `direction: "in"`.

- [ ] **Step 1: Write failing tests for direction preservation and idempotent duplicate import.**
- [ ] **Step 2: Run tests and confirm RED.**
- [ ] **Step 3: Refactor fan-out into a reusable `queueEncryptedDelivery()` helper used by recipient delivery and self sync.**
- [ ] **Step 4: Send sync copies to own devices except current device, preferring one-time prekeys.**
- [ ] **Step 5: Receive sync copies without creating inbox entries and dedupe on the stable message ID.**
- [ ] **Step 6: Run tests/build/lint; commit when green.**

### Task 8: Durable registry branch/configuration and release verification

**Files:**
- Modify: `README.md`
- Create: `docs/V1.1-SECURE-SYNC.md`
- No secret values committed.

**Interfaces:**
- GitHub branch `registry` exists.
- Render non-secret registry env points to `XDSawyerLoL/QuanticMail`, branch `registry`.
- `QUANTIC_GITHUB_TOKEN` is required for runtime writes; if unavailable to the automation, status remains explicitly memory/degraded and release notes state the blocker.

- [ ] **Step 1: Create `registry` branch if absent.**
- [ ] **Step 2: Set non-secret Render environment values for owner/repo/branch without replacing existing variables.**
- [ ] **Step 3: Verify `/api/quantic/registry/status`; only call the durable registry active if it returns `{configured:true, mode:"github"}`.**
- [ ] **Step 4: Document V1.1 security properties, fallback semantics, QR pairing and recovery behavior.**
- [ ] **Step 5: Run fresh `npm test`, `npm run build`, `npm run lint`, VPS bootstrap validation and production compose validation in CI.**
- [ ] **Step 6: Open/update PR, inspect changed files, merge only with green CI.**
- [ ] **Step 7: Verify Render builds the merge commit, exposes the new routes and reaches `live`.**
