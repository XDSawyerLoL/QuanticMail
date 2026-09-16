# QuanticMail

QuanticMail is the local-first messaging product of Quantic Sillage.

QuanticMail does not use Gmail-style hosted mailboxes or SMTP as its core transport. Quantic Network uses human identities such as `sansa@quantic` and self-certifying canonical identities derived from a signing key.

## V1.1 architecture

- **Human identity:** `name@quantic`
- **New canonical identities:** `name~<32 hex>@quantic` (128-bit displayed fingerprint)
- **Legacy canonical identities:** existing 10-hex identities remain valid and are not silently renamed
- **Root device:** retains the master identity signing private key
- **Linked devices:** each has its own ECDH P-256 encryption key, ECDSA P-256 device-signing key and auth token
- **Device authorization:** root-signed Quantic device certificates plus a signed monotonic identity manifest
- **Message encryption:** AES-256-GCM with ECDH P-256
- **One-time prekeys:** per-device signed P-256 ECDH prekeys, atomically claimed once by the relay when available
- **Fallback:** static per-device ECDH encryption remains available when the prekey pool is empty or unavailable
- **Multi-device delivery:** one independently encrypted transport envelope per authorized recipient device
- **Sent-history sync:** encrypted sync copies are sent to the sender's other authorized devices
- **Local mailbox:** browser IndexedDB
- **Durable local outbox:** encrypted deliveries remain local until delivery receipts arrive
- **Identity recovery:** password-encrypted `.quantic-vault` for the root identity
- **QR pairing:** 256-bit pairing secret in the URL fragment, HKDF-SHA-256 + AES-256-GCM package encryption, 10-minute rendezvous and one-shot package retrieval
- **Directory and temporary relay:** Render
- **Optional durable manifest registry:** GitHub `registry` branch when the Render service has a write token configured

Private identity, device and one-time-prekey keys remain client-side. The relay sees routing metadata and ciphertext but does not receive readable message bodies or private cryptographic keys.

## Current deployment

- **Web application:** `https://quanticmail.onrender.com`
- **Device manager / QR pairing:** `https://quanticmail.onrender.com/devices`
- **File-pairing fallback:** `https://quanticmail.onrender.com/devices/files`
- **Identity Vault:** `https://quanticmail.onrender.com/vault`
- **Network:** Quantic Network V1.1 alpha

## V1.1 capabilities

- create a new 128-bit canonical Quantic identity while preserving legacy 40-bit identities
- prove root ownership with ECDSA P-256
- authorize independent devices with root-signed certificates
- maintain a root-signed monotonic device manifest with revocations and rollback protection
- pair a new PC or phone through a short-lived QR rendezvous without copying the master private key
- bootstrap the new device with an encrypted copy of available local history
- publish signed one-time prekeys for each authorized device
- atomically claim and consume a recipient prekey when available
- fall back to the authorized device's static key when no prekey is available
- encrypt one transport delivery per recipient device
- synchronize readable sent-history records to the sender's other authorized devices through encrypted `sync-copy` deliveries
- keep per-device relay queues and delivery receipts isolated
- keep unsent encrypted deliveries in a local durable outbox
- preserve V0.8 Identity Vault recovery for the root identity
- optionally checkpoint signed manifests to a GitHub registry branch

See [`docs/V1.1-SECURE-SYNC.md`](docs/V1.1-SECURE-SYNC.md).

## QR pairing flow

1. On the existing root device, open `/devices` and create a QR invitation.
2. QuanticMail generates a random 256-bit secret locally. The secret is placed in the URL fragment (`#secret=...`), so normal HTTP requests do not send it as part of the URL path or query string.
3. Scan the QR code on the new device and choose a device label.
4. The new device creates its own encryption/signing keys locally and submits only its public request through the temporary pairing rendezvous.
5. The root device explicitly approves the request, signs the device certificate, increments/signs the manifest and encrypts a bootstrap package containing the certificate, manifest and available local history.
6. The new device downloads that encrypted package once, decrypts it locally, verifies the signed manifest/certificate and registers with its own auth token.
7. The fallback file-pairing workflow remains available under `/devices/files`.

Pairing invitations expire after 10 minutes. The server stores only the temporary rendezvous state and encrypted package; the pairing secret is never persisted by the application server.

## One-time prekeys

Each V1.1 device keeps private one-time ECDH keys in IndexedDB and publishes only signed public prekey records. The relay verifies the device signature against the current signed manifest before accepting them.

When a sender targets a device, it authenticates and atomically claims one public prekey. The prekey identifier is carried inside the standard JWK `kid` metadata on the ephemeral envelope key, preserving the existing V1 relay envelope shape. After authenticated decryption and local message persistence, the recipient deletes the corresponding local private prekey.

If no one-time prekey is available, QuanticMail uses the authorized device's static ECDH key as an explicit compatibility/degraded-security fallback instead of making delivery impossible.

## Sent-history sync

A logical outgoing message has one stable message ID. Normal recipient deliveries and encrypted copies sent to the sender's other active devices carry that same logical ID.

A sync copy is transported back to the sender's own canonical identity but retains the external logical recipient inside the encrypted payload. On receipt, it is validated and stored as an **outgoing** message. IndexedDB's message key makes repeated history imports/idempotent sync overwrite the same logical record instead of creating duplicates.

## Durable manifest registry

Render Free storage is ephemeral, so QuanticMail does not treat process memory as the durable authority for device authorization. Signed manifests can be checkpointed to the repository's `registry` branch.

Runtime configuration:

- `QUANTIC_GITHUB_TOKEN`: GitHub token with permission to read/write repository contents
- `QUANTIC_GITHUB_OWNER`: defaults to `XDSawyerLoL`
- `QUANTIC_GITHUB_REPO`: defaults to `QuanticMail`
- `QUANTIC_GITHUB_BRANCH`: defaults to `registry`

If `QUANTIC_GITHUB_TOKEN` is absent, QuanticMail deliberately reports registry mode as `memory`; it does not pretend durable GitHub persistence is active. A token must be provided through Render environment variables, never committed to this repository.

## Zero-cost durability model

The current Render Free service can restart and lose process-memory relay state. QuanticMail therefore relies on cryptographically portable client state rather than pretending the free relay is permanent storage:

- root ownership is proven by the master signing key;
- device authorization is proven by root-signed certificates and manifests;
- linked devices re-register from their local certificates after a restart;
- undelivered encrypted payloads remain in the sender's IndexedDB outbox;
- readable mailbox history remains on user devices and can be bootstrapped during pairing;
- optional GitHub checkpoints preserve signed manifest state when explicitly configured.

Temporary relay queues can still be lost by a Render restart before delivery. V1.1 reduces the impact through local retry/outbox logic but does not claim server-side durable message storage.

## Security boundary and current limitations

QuanticMail V1.1 is an **alpha protocol implementation and has not received an independent security audit**. ECDH/ECDSA currently use P-256 and message encryption uses AES-256-GCM.

One-time-prekey pool state on the free relay is process-memory state. After a relay restart devices replenish fresh prekeys rather than treating the relay as a durable prekey authority. Static-key fallback is intentionally visible in the protocol design and means forward-secrecy properties are not uniform for every delivery.

The root device can authorize/revoke linked devices because it retains the master signing private key. Linked devices do not receive that master private key.

## Legacy mail work

The repository still contains earlier JMAP/Stalwart and Resend experiments for reference. They are no longer the default product direction.

Quantic Network communication between Quantic identities does not require SMTP, MX, IMAP, SPF, DKIM, DMARC, a purchased domain, or a Gmail/Outlook account.
