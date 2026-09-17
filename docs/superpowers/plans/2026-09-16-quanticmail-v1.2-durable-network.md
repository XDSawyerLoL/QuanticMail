# QuanticMail V1.2 Durable Network Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Strengthen new device IDs to 128 bits and make V1.1 manifests/prekeys durable on the standalone Quantic Relay without breaking legacy devices.

**Architecture:** Preserve the existing V1.1 browser/web protocol and extend shared protocol helpers so both Next.js and the standalone Node relay accept legacy and strong device IDs. Upgrade the standalone relay state file to V2, storing signed manifests and prekey pools atomically alongside existing durable queues. Keep pairing ephemeral and GitHub registry optional.

**Tech Stack:** TypeScript, Node.js 22+ built-in test runner, Next.js 16, WebCrypto/P-256, Node `crypto`, JSON atomic file storage.

**Spec:** `docs/superpowers/specs/2026-09-16-quanticmail-v1.2-durable-network-design.md`

## Global Constraints

- Existing `d-<10 hex>` IDs remain valid for already-issued certificates/manifests.
- New devices use `d-<32 hex>`.
- Never mutate an already-signed certificate solely to migrate its device ID.
- Pairing rendezvous remain ephemeral.
- GitHub stores signed manifests only; never plaintext messages or private keys.
- Standalone relay must work without GitHub or paid infrastructure.
- All persistent standalone mutations remain atomic and rollback on storage failure.

---

### Task 1: Shared strong device ID protocol

**Files:**
- Create: `lib/quantic/device-id-core.mjs`
- Create: `lib/quantic/device-id-core.d.mts`
- Modify: `lib/quantic/device.ts`
- Modify: `lib/quantic/relay.ts`
- Modify: `lib/quantic/manifest-core.mjs`
- Test: `tests/device-id-v12.test.mjs`
- Test: `tests/manifest-core.test.mjs`

**Interfaces:**
- Produces `deviceDigestHex(key)`, `deviceIdForPublicKey(key, length = 32)`, `isValidDeviceId(value)`, `assertDeviceIdMatchesKey(deviceId, key)`.
- New browser devices call the 32-hex derivation.
- Server certificate verification accepts 10 or 32 and verifies the matching digest prefix.

- [ ] **Step 1: Write failing tests** for deterministic strong IDs, legacy IDs, invalid prefixes, and manifest acceptance of both lengths.
- [ ] **Step 2: Run `npm test`** and confirm only the new V1.2 assertions fail.
- [ ] **Step 3: Implement `device-id-core.mjs`** using SHA-256 over `P-256:<x>:<y>` and exact 10/32-prefix validation.
- [ ] **Step 4: Update browser device creation** so `createPendingDevice()` emits strong IDs while certificate install remains compatible with legacy IDs.
- [ ] **Step 5: Update relay certificate/root handling** so strong canonical identities derive strong root IDs, legacy identities preserve 10-hex root IDs, and linked certificates accept either valid prefix.
- [ ] **Step 6: Update manifest validator** from 10-only to 10-or-32 device IDs.
- [ ] **Step 7: Run `npm test`, `npm run build`, `npm run lint`** and require green.
- [ ] **Step 8: Commit** `feat: strengthen Quantic device identifiers`.

### Task 2: Relay persistent state V2

**Files:**
- Modify: `lib/quantic/relay-state.ts`
- Modify: `standalone-relay/runtime.ts`
- Modify: `standalone-relay/storage.ts`
- Create: `lib/quantic/standalone-v11-state.ts`
- Test: `tests/relay-state-v2.test.ts`
- Test: `tests/relay-runtime-v11.test.ts`

**Interfaces:**
- `RelayPersistentStateV2` extends state with `manifests`, `preKeyPools`, `consumedPreKeys`.
- `restoreRelayState()` accepts V1 and V2; V1 maps to empty V1.1 stores.
- `exportRelayState()` always emits V2.
- `standalone-v11-state.ts` exposes shared accessors for manifest and prekey state backed by the same global runtime state.

- [ ] **Step 1: Write failing V1→V2 migration and V2 restart tests.**
- [ ] **Step 2: Verify RED** with `node --experimental-transform-types --test tests/relay-state-v2.test.ts tests/relay-runtime-v11.test.ts`.
- [ ] **Step 3: Extend relay state types and serializers** to V2 while retaining V1 restore compatibility.
- [ ] **Step 4: Validate persisted manifests** with existing manifest signature/shape verification during restore.
- [ ] **Step 5: Prune expired prekeys/tombstones** during restore and reject structurally corrupt records.
- [ ] **Step 6: Ensure runtime rollback snapshots include V1.1 state.**
- [ ] **Step 7: Run focused tests then full suite.**
- [ ] **Step 8: Commit** `feat: persist V1.1 relay state`.

### Task 3: Standalone manifest endpoints

**Files:**
- Create: `lib/quantic/standalone-manifest.ts`
- Modify: `standalone-relay/http.ts`
- Test: `tests/standalone-relay-v11-http.test.ts`

**Interfaces:**
- `publishStandaloneManifest(manifest)` verifies signature and uses `mergeManifestState`.
- `getStandaloneManifest(canonical)` returns the local durable signed manifest or null.
- HTTP supports `GET/POST /api/quantic/manifest` and `POST /api/quantic/devices/revoke`.

- [ ] **Step 1: Write failing HTTP tests** for publish/get, rollback rejection and same-sequence fork rejection.
- [ ] **Step 2: Verify RED.**
- [ ] **Step 3: Implement standalone manifest service** using shared manifest core/node verification.
- [ ] **Step 4: Wire HTTP routes through `RelayRuntime.read/mutate`.**
- [ ] **Step 5: Test persistence across standalone restart.**
- [ ] **Step 6: Run full test/build/lint.**
- [ ] **Step 7: Commit** `feat: add durable manifest API to standalone relay`.

### Task 4: Standalone prekey endpoints

**Files:**
- Create: `lib/quantic/standalone-prekeys.ts`
- Modify: `standalone-relay/http.ts`
- Test: `tests/standalone-relay-v11-http.test.ts`
- Test: `tests/standalone-relay-prekey-restart.test.ts`

**Interfaces:**
- Uses durable manifest state to find the active device signing key.
- Uses existing `prekey-core.mjs` and `prekey-pool.mjs` semantics over the V2 persisted store.
- HTTP supports publish, claim and status routes with the same body/query contract as the web relay.

- [ ] **Step 1: Write failing publish/status/claim and restart tests.**
- [ ] **Step 2: Verify RED.**
- [ ] **Step 3: Implement authenticated prekey publication** with manifest/device signature checks.
- [ ] **Step 4: Implement atomic claim + consumed tombstone** in a runtime mutation.
- [ ] **Step 5: Implement status read.**
- [ ] **Step 6: Verify claimed prekey cannot be reclaimed or republished after restart.**
- [ ] **Step 7: Run full suite/build/lint.**
- [ ] **Step 8: Commit** `feat: persist one-time prekeys on standalone relay`.

### Task 5: Client relay compatibility and routing

**Files:**
- Modify: `lib/quantic/relay-client.ts`
- Modify: `components/quantic-network-v11-app.tsx` only if route capability handling requires it
- Modify: `components/relay-settings.tsx` only if capability/status display requires it
- Test: `tests/relay-client.test.ts`

**Interfaces:**
- V1.1 API calls must use the selected/failover relay rather than hard-code same-origin where practical.
- Bootstrap web relay remains a fallback.
- A standalone relay advertising protocol capabilities can service manifest/prekey routes.

- [ ] **Step 1: Add failing client tests** proving V1.1 route construction and failover behavior.
- [ ] **Step 2: Verify RED.**
- [ ] **Step 3: Extend relay client helper** for manifest/prekey endpoints using existing relay ordering/failover rules.
- [ ] **Step 4: Route V1.1 calls through shared client helper** without changing crypto payloads.
- [ ] **Step 5: Run full tests/build/lint.**
- [ ] **Step 6: Commit** `feat: route V1.1 protocol through standalone relays`.

### Task 6: GitHub registry privacy and activation diagnostics

**Files:**
- Modify: `lib/quantic/registry-store.ts`
- Modify: `.env.example`
- Modify: `README.md`
- Test: `tests/registry-store-guard.test.mjs` or existing registry test file

**Interfaces:**
- Registry commit messages must not include `canonicalAddress`.
- `/api/quantic/registry/status` remains the runtime truth for `memory` vs `github` mode.
- Environment documentation lists all four `QUANTIC_GITHUB_*` variables and minimum token permission (`Contents: read/write` on the single repository).

- [ ] **Step 1: Write failing privacy test** ensuring generated checkpoint commit message contains no canonical address.
- [ ] **Step 2: Verify RED.**
- [ ] **Step 3: Extract/build a non-revealing checkpoint message** based on sequence and registry path digest only.
- [ ] **Step 4: Document Render environment setup** without committing a token.
- [ ] **Step 5: Run tests/build/lint.**
- [ ] **Step 6: Commit** `fix: harden durable registry privacy`.

### Task 7: V1.2 release verification

**Files:**
- Modify: `package.json` version to `1.2.0`
- Create/Modify: `docs/V1.2-DURABLE-NETWORK.md`
- Modify: `README.md`

**Interfaces:**
- Release documentation distinguishes locally durable standalone state from optional GitHub checkpoint durability.

- [ ] **Step 1: Update release docs and package version.**
- [ ] **Step 2: Run complete CI-equivalent locally through GitHub Actions:** `npm test`, `npm run build`, `npm run lint`, standalone relay CLI smoke, VPS bootstrap validation and compose validation.
- [ ] **Step 3: Open/refresh PR and require green CI.**
- [ ] **Step 4: Review diff for migration/security regressions.**
- [ ] **Step 5: Merge only with green final HEAD.**
- [ ] **Step 6: Let Render auto-deploy `main`; do not manually trigger.**
- [ ] **Step 7: Verify Render deployment is `live`, Next startup is ready, and V1.2 routes exist.**
- [ ] **Step 8: Report registry mode truthfully; if no token is available, leave mode `memory` and state the exact external setup still required.**
