# QuanticMail V1.2 Durable Network Design

## Goal

Make QuanticMail survive Render process restarts without weakening the V1.1 protocol, while strengthening new device identifiers from 40 bits to 128 bits and preserving compatibility with every already-authorized V1.0/V1.1 device.

## Scope

V1.2 changes three connected parts of Quantic Network:

1. **Strong device identifiers** for newly created devices.
2. **Standalone Relay V1.1 durability** for signed manifests and one-time prekeys in addition to the already-durable identities, queues, receipts and devices.
3. **Optional GitHub registry activation path** for durable signed identity checkpoints when a Render secret is supplied.

Pairing rendezvous remain intentionally ephemeral. Message plaintext never goes to GitHub.

## Existing state

The standalone relay already persists `RelayPersistentState` to `relay-state.json` with atomic temp-file + rename semantics. That state contains identities, aliases, device authorizations, encrypted message queues, receipts, challenges and send-rate windows. The V1.1 manifest cache and prekey pools are separate in-memory globals and are not currently served by the standalone relay HTTP surface.

The web app already supports signed manifests, one-time prekeys, QR pairing, multi-device sync and optional GitHub registry checkpoints.

## Device IDs

### Formats

V1.2 recognizes both:

- legacy: `d-` + 10 lowercase hexadecimal characters (40-bit display prefix),
- strong: `d-` + 32 lowercase hexadecimal characters (128-bit prefix).

New devices created by V1.2 MUST use the 32-hex form.

Existing 10-hex device IDs MUST remain valid indefinitely for previously-authorized devices, certificates, manifests, queues and receipts.

### Derivation

A device ID is derived from SHA-256 over the canonical EC public point string:

`P-256:<x>:<y>`

The strong form uses the first 32 hexadecimal characters of the SHA-256 digest. The legacy form uses the first 10.

### Migration rules

- Never mutate an existing signed certificate merely to lengthen its device ID.
- Never rewrite an existing manifest entry solely to lengthen its device ID.
- A newly-created linked device always receives a strong ID.
- A new V1.2 root identity receives a strong root device ID.
- A legacy root identity keeps its existing root device ID when re-registering.
- Certificate verification accepts 10 or 32 hex and verifies that the supplied ID matches the corresponding prefix of the device public-key digest.
- Manifest validation accepts 10 or 32 hex device IDs.
- Queue and receipt keys continue to use the exact authorized device ID string, so historical delivery remains addressable.

## Standalone Relay V1.1 durability

### Persistent state version

Introduce `quantic-relay-state` **version 2**. Version 2 extends version 1 with:

- `manifests`: signed identity manifests keyed by canonical address,
- `preKeyPools`: available signed prekeys keyed by `<canonicalAddress>#<deviceId>`,
- `consumedPreKeys`: prekey tombstones keyed by `preKeyId` with their expiry timestamp.

Version 1 files remain readable and migrate in memory to version 2 with empty manifests and prekey state.

### What remains ephemeral

Pairing invitations, their 256-bit secret hashes, pending pairing requests and encrypted pairing packages are NOT persisted. They expire after ten minutes and are recreated after relay restart. This avoids turning temporary rendezvous secrets into durable disk state.

### Manifest rules

Standalone Relay manifest publication must use the same signature verification, anti-rollback, fork detection, revocation preservation and canonical-address rules as the web relay.

The standalone relay becomes authoritative for its own local manifest store. It does not require GitHub to function.

### Prekey rules

Standalone Relay must expose the same V1.1 semantics as the web relay:

- authenticated publication,
- maximum 64 available prekeys per device,
- signature verification against the active device signing key in the manifest,
- atomic claim,
- tombstone after claim,
- no re-publication of a consumed prekey before its expiry,
- expired records and tombstones pruned on load and mutation.

The available pool and consumed tombstones are persisted in the same atomic relay state transaction as the rest of the relay state.

## Standalone Relay HTTP surface

Add V1.1-compatible routes:

- `GET /api/quantic/manifest?canonical=...`
- `POST /api/quantic/manifest`
- `POST /api/quantic/devices/revoke`
- `POST /api/quantic/prekeys/publish`
- `POST /api/quantic/prekeys/claim`
- `GET /api/quantic/prekeys/status`

The existing routes remain unchanged.

Pairing routes are not required for the first V1.2 durable-relay milestone because pairing can continue through the bootstrap web relay and produces a signed device certificate + manifest that any standalone relay can subsequently verify. A future relay-local pairing extension can be added without changing persistent state.

## Runtime transaction model

All standalone relay mutations remain serialized through `RelayRuntime.mutate()`.

For operations that modify manifest or prekey state, the runtime must snapshot and persist the complete V2 state atomically. If persistence fails, in-memory state is rolled back to the pre-operation snapshot.

Reads wait for the mutation tail exactly as they do today.

## GitHub registry

GitHub remains an optional signed checkpoint for identity manifests only.

Configuration remains:

- `QUANTIC_GITHUB_TOKEN`
- `QUANTIC_GITHUB_OWNER` (default `XDSawyerLoL`)
- `QUANTIC_GITHUB_REPO` (default `QuanticMail`)
- `QUANTIC_GITHUB_BRANCH` (default `registry`)

No token is committed to the repository.

V1.2 additionally removes the canonical address from registry commit messages. Commit messages use a non-revealing registry path hash or generic sequence text to avoid leaking a human-readable canonical identity through Git history.

If `QUANTIC_GITHUB_TOKEN` is absent, web-runtime registry mode remains `memory`; standalone relays still provide durable local state.

## Failure handling

- Corrupt relay-state JSON: fail startup with a clear error instead of silently discarding state.
- Unknown future state version: fail startup.
- V1 state: migrate to V2 in memory and save as V2 on the next mutation/flush.
- Invalid persisted manifest: fail startup rather than trusting it.
- Invalid persisted prekey: discard expired entries, but reject structurally malformed signed records that could indicate state corruption.
- Same-sequence manifest fork: reject with conflict.
- Older manifest: reject rollback.
- Storage write failure: roll back the in-memory mutation.

## Security properties

V1.2 improves collision resistance for new device routing IDs from 40-bit prefixes to 128-bit prefixes. Legacy IDs remain accepted only for compatibility and remain bound to their full public key/certificate/manifests.

One-time prekeys remain private-key-local: only signed public prekeys are stored by relays. Claimed prekeys are tombstoned server-side and their corresponding private keys are deleted client-side after decryption, preserving V1.1 forward-secrecy behavior.

The relay stores encrypted envelopes and routing metadata, never message plaintext.

## Testing requirements

### Device ID tests

- new helper returns `d-` plus exactly 32 lowercase hex,
- deterministic for a public key,
- legacy helper still produces the historical 10-hex form,
- certificate verification accepts valid 10-hex legacy IDs,
- certificate verification accepts valid 32-hex strong IDs,
- certificate verification rejects either length when the digest prefix is wrong,
- manifest shape accepts 10- and 32-hex IDs,
- new pending devices use 32-hex IDs.

### Relay persistence tests

- V1 state restores and migrates with empty V1.1 stores,
- V2 manifest survives process/runtime restart,
- V2 available prekey pool survives restart,
- consumed prekey tombstone survives restart and blocks re-publication,
- expired prekeys/tombstones disappear after restore,
- invalid manifest state fails restore,
- storage failure rolls back V1.1 state.

### HTTP tests

- standalone manifest publish/get roundtrip,
- rollback and same-sequence fork rejected,
- prekey publish/status/claim works through HTTP,
- claimed prekey cannot be claimed or republished again,
- legacy device IDs continue to authenticate,
- strong device IDs authenticate and route envelopes.

### Release verification

- complete unit/integration suite,
- Next.js production build,
- ESLint,
- standalone relay CLI smoke test,
- restart test with V2 persisted state,
- existing VPS bootstrap validation,
- Render deployment verification after merge.

## Non-goals

- No Double Ratchet rewrite in V1.2.
- No message plaintext or private keys in GitHub.
- No migration that changes an already-issued device certificate.
- No mandatory GitHub dependency for standalone relays.
- No database service or paid infrastructure requirement.
