# QuanticMail V1.1 Secure Sync Design

## Goal

Extend the deployed V1.0 signed-manifest protocol without breaking existing identities. V1.1 adds stronger new canonical identifiers, short-lived QR pairing, encrypted history bootstrap, sent-history replication across devices, and one-time ECDH prekeys that provide forward-secrecy improvement when available.

## Compatibility contract

- Existing V1.0 canonical addresses ending in a 10-hex fingerprint remain valid and routable.
- Existing stored identities MUST NOT be silently renamed on startup.
- New V1.1 identities use a 32-hex (128-bit) canonical fingerprint derived from the same SHA-256 identity-signing-key digest.
- Parsers and relay routing accept canonical fingerprints of exactly 10 or 32 lower-case hex characters during migration.
- The human alias `handle@quantic` remains unchanged.
- V1.0 manifests remain valid; V1.1 extends device/runtime state without requiring a destructive manifest rewrite.

## 1. Durable registry

The existing GitHub-backed registry remains the durable checkpoint mechanism.

Runtime configuration:

- `QUANTIC_GITHUB_OWNER=XDSawyerLoL`
- `QUANTIC_GITHUB_REPO=QuanticMail`
- `QUANTIC_GITHUB_BRANCH=registry`
- `QUANTIC_GITHUB_TOKEN=<fine-grained token with Contents write access to XDSawyerLoL/QuanticMail>`

The `registry` branch is created once. Registry file paths remain SHA-256-derived and do not expose canonical addresses in filenames. Manifest signatures remain the trust boundary: GitHub can persist or withhold a checkpoint but cannot forge a valid identity state.

If the token is absent or GitHub is unavailable, QuanticMail runs in degraded memory mode and surfaces that state. The runtime MUST never claim durable persistence while `registryStatus().configured` is false.

## 2. V1.1 one-time prekeys

Each authorized device maintains a local pool of 32 one-time ECDH P-256 key pairs.

A public prekey record contains:

- `version: 1`
- `canonicalAddress`
- `deviceId`
- `preKeyId` (128-bit random identifier encoded as hex/base64url)
- `publicKey` (P-256 ECDH JWK)
- `createdAt`
- `expiresAt` (7 days after creation)
- `signature` made with the device-signing private key over deterministic canonical text

Private prekeys never leave IndexedDB.

The relay exposes:

- `POST /api/quantic/prekeys/publish` — authenticated device publishes/replenishes unused signed public prekeys.
- `POST /api/quantic/prekeys/claim` — sender requests one prekey for a specific canonical identity/device. Claim atomically removes that prekey from relay memory and returns it once.
- `GET /api/quantic/prekeys/status` — authenticated device sees approximate pool depth for itself.

Before encryption, the sender attempts a prekey claim. If a valid signed prekey is available, the message is encrypted to that public key and the envelope carries `preKeyId`. If no prekey is available, encryption falls back to the device's manifest ECDH public key and marks the envelope `keyMode: "static-fallback"`.

On successful decryption of a `one-time-prekey` envelope, the receiver deletes the matching private prekey before acknowledging delivery. Replays using the same `preKeyId` then cannot be decrypted again from local state.

This is explicitly not described as a Double Ratchet or Signal-equivalent protocol. It is a real one-time-prekey forward-secrecy improvement for messages that use a claimed prekey, with an explicit static-key fallback for availability.

## 3. QR pairing rendezvous

Pairing remains root-authorized, but files stop being the primary UX.

### Invite creation

The root device generates:

- `inviteId`: random 128-bit identifier
- `secret`: random 256-bit pairing secret
- expiry: 10 minutes

The relay stores only `inviteId`, SHA-256(secret), canonical address, root device ID, timestamps and transient pairing state.

The root displays a QR containing:

`https://quanticmail.onrender.com/devices?pair=<inviteId>#secret=<base64url-secret>`

The fragment is not transmitted as part of the HTTP request. A copyable link and the existing request/certificate files remain fallbacks.

### New-device request

The new device opens the link, reads `pair` and `#secret`, generates its independent ECDH and ECDSA device keys locally, then submits only its public request to the pairing rendezvous while authenticating with the secret.

### Root approval

The root polls the invite, displays the new device label + device ID, and requires an explicit approval click. Approval:

1. signs the normal device certificate;
2. adds the device to the signed manifest;
3. creates a history snapshot from local messages;
4. encrypts `{certificate, manifest, history}` using an AES-256-GCM key derived from the 256-bit invite secret with HKDF-SHA-256 and `inviteId` as context;
5. uploads only the encrypted package to the rendezvous.

The new device downloads and decrypts the package, validates the certificate and manifest, installs its local identity, imports the history snapshot, then deletes the local pairing secret. The relay deletes the invite state after successful pickup or expiry.

Maximum encrypted pairing package: 4 MiB. History is truncated newest-first if required to fit the limit, and the UI reports that the bootstrap snapshot was partial.

## 4. History sync after pairing

Initial history is imported from the encrypted pairing package.

For ongoing synchronization:

- received messages already fan out to every authorized recipient device;
- after a user sends a message to another identity, the sending device also creates encrypted `sync-copy` envelopes for every other active device on its own identity;
- a sync copy contains the same message ID, recipients, subject, body, created time and `direction: "out"`;
- receiving devices store sync copies as outgoing history, not as inbound mail;
- IndexedDB's message key (`id`) provides idempotent deduplication.

Sync copies use the same one-time-prekey preference and static fallback rules as normal deliveries.

No plaintext history or contacts are stored on Render or GitHub.

## 5. Strong canonical identifiers

V1.1 introduces `fingerprintPublicKeyStrong(publicJwk)` which returns the first 32 hex characters (128 bits) of the existing SHA-256 canonical signing-key digest.

Rules:

- `fingerprintPublicKey()` remains the legacy 10-hex helper for compatibility and migration tests.
- New V1.1 identity creation uses the strong helper.
- Existing identities preserve their stored `fingerprint` and `canonicalAddress` exactly.
- Server canonical-locator validation accepts 10 or 32 hex characters.
- UI may abbreviate the 32-hex fingerprint for display, but copy/routing always uses the full locator.

## 6. Local storage

IndexedDB version increments from 5 to 6 and adds a `prekeys` object store keyed by `preKeyId`.

Local prekey record:

- public record fields listed above, excluding signature duplication where unnecessary;
- private ECDH JWK;
- `state: "unused" | "claimed"` where local state moves to claimed only after an incoming envelope references it;

Required operations:

- save prekeys in batch;
- list unused, unexpired prekeys;
- find by preKeyId;
- delete by preKeyId;
- count available prekeys.

Pairing invite secrets remain in memory/sessionStorage only, not long-term IndexedDB.

## 7. Relay state and validation

Prekey pools and pairing rendezvous data are transient memory state. A Render restart can discard them. Clients recover by republishing unused local public prekeys and by recreating an expired pairing invite.

Every prekey claim validates:

- canonical identity exists;
- device is currently active in the latest signed manifest when one exists;
- device-signing key matches the manifest/certificate record;
- prekey signature is valid;
- prekey is unexpired;
- prekey has not already been claimed.

Pairing endpoints enforce 10-minute expiry, constant-time secret-hash comparison where practical, payload size limits and one-time package pickup.

## 8. Security boundaries

V1.1 guarantees only what the implementation can prove:

- private identity/device/prekey keys stay client-side;
- root manifest signatures authorize and revoke devices;
- one-time-prekey messages gain protection against later compromise of the device's long-term ECDH key after the one-time private prekey has been deleted;
- static fallback messages do not gain that property;
- pairing package confidentiality depends on the 256-bit random QR secret and AES-GCM/HKDF implementation;
- GitHub registry durability depends on a configured repository token but not on trusting GitHub to sign identity state.

The protocol remains alpha and unaudited. UI and documentation must not claim Signal-equivalent security, full decentralization, or mathematically complete forward secrecy.

## 9. Tests and acceptance criteria

Automated tests must cover:

1. strong fingerprint length and deterministic output;
2. legacy and strong canonical locator acceptance;
3. prekey signature verification and tamper rejection;
4. expired prekey rejection;
5. atomic single claim and second-claim failure;
6. local private prekey deletion after successful decrypt;
7. static fallback when pool is empty;
8. pairing invite expiry;
9. incorrect pairing secret rejection;
10. encrypted pairing package round-trip;
11. tampered package rejection;
12. history snapshot import deduplication;
13. outgoing sync-copy direction preservation;
14. revoked-device prekey claim rejection;
15. V1.0 manifest/identity compatibility;
16. registry status accurately reports configured vs memory mode.

Release gate remains: `npm test`, `npm run build`, `npm run lint`, deployment validation, merge to `main`, then Render `live` verification.