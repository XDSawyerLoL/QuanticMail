# QuanticMail

QuanticMail is the local-first messaging product of Quantic Sillage.

QuanticMail does not use Gmail-style hosted mailboxes or SMTP as its core transport. Quantic Network uses human identities such as `sansa@quantic` and self-certifying canonical identities derived from a signing key.

## Current architecture

- **Human identity:** `name@quantic`
- **New canonical identities:** `name~<32 hex>@quantic` (128-bit displayed fingerprint)
- **Legacy canonical identities:** existing 10-hex identities remain valid and are not silently renamed
- **Root device:** retains the master identity signing private key
- **Linked devices:** each has independent encryption/signing material and its own auth token
- **Device authorization:** root-signed Quantic device certificates plus a signed monotonic identity manifest
- **Classical compatibility:** P-256 ECDH/ECDSA remains supported
- **Crypto V2:** ML-KEM-768 + ML-DSA-65 hybrid protection can be activated through a signed Crypto Profile; `hybrid-required` is downgrade-protected
- **Message encryption:** AES-256-GCM, with hybrid P-256 + ML-KEM key derivation when Crypto V2 requires it
- **One-time prekeys:** per-device signed P-256 ECDH prekeys, atomically claimed once by the relay when available
- **Multi-device delivery:** one independently encrypted transport envelope per authorized recipient device
- **Sent-history sync:** encrypted sync copies are sent to the sender's other authorized devices
- **Local mailbox:** browser IndexedDB
- **Durable local outbox:** encrypted deliveries remain local until delivery receipts arrive
- **Identity recovery:** password-encrypted `.quantic-vault` for the root identity
- **QR pairing:** 256-bit pairing secret in the URL fragment, HKDF-SHA-256 + AES-256-GCM package encryption, 10-minute rendezvous and one-shot package retrieval
- **Federation:** independent Quantic relays can exchange signed portable envelopes and delivery receipts
- **Discovery Mesh:** standalone relays discover signed identity/route/Crypto Profile bundles through a bounded Kademlia-style peer mesh
- **Optional GitHub checkpoint:** signed identity manifests can still be checkpointed to the `registry` branch when explicitly configured

Private identity, device, one-time-prekey and post-quantum private keys remain client-side. Relays see routing metadata and ciphertext but do not receive readable message bodies or private cryptographic keys.

## Current deployment

- **Web application:** `https://quanticmail.onrender.com`
- **Device manager / QR pairing:** `https://quanticmail.onrender.com/devices`
- **File-pairing fallback:** `https://quanticmail.onrender.com/devices/files`
- **Identity Vault:** `https://quanticmail.onrender.com/vault`
- **Protocol stack:** QuanticMail V1.2 + Federation + Crypto V2 + Discovery Mesh support

The current Render deployment runs the Next web application. It is **not**, by itself, a public node of the standalone Discovery Mesh. Discovery Mesh runs in the standalone relay process described below.

## Secure multi-device messaging

QuanticMail can:

- create a new 128-bit canonical Quantic identity while preserving legacy 40-bit identities;
- prove root ownership with ECDSA P-256;
- authorize independent devices with root-signed certificates;
- maintain a signed monotonic device manifest with revocations and rollback protection;
- pair a new PC or phone through a short-lived QR rendezvous without copying the master private key;
- bootstrap the new device with an encrypted copy of available local history;
- publish signed one-time prekeys for each authorized device;
- atomically claim and consume a recipient prekey when available;
- fall back to an authorized device's static P-256 key when no prekey is available;
- synchronize sent-history records to the sender's other devices;
- retain unsent encrypted deliveries in a durable local outbox;
- optionally activate Crypto V2 hybrid protection and prevent a silent downgrade once `hybrid-required` is pinned.

See [`docs/V1.1-SECURE-SYNC.md`](docs/V1.1-SECURE-SYNC.md) for the secure-sync foundation.

## QR pairing flow

1. On the existing root device, open `/devices` and create a QR invitation.
2. QuanticMail generates a random 256-bit secret locally. The secret is placed in the URL fragment (`#secret=...`), so normal HTTP requests do not send it as part of the URL path or query string.
3. Scan the QR code on the new device and choose a device label.
4. The new device creates its own encryption/signing keys locally and submits only its public request through the temporary pairing rendezvous.
5. The root device explicitly approves the request, signs the device certificate, increments/signs the manifest and encrypts a bootstrap package containing the certificate, manifest and available local history.
6. The new device downloads that encrypted package once, decrypts it locally, verifies the signed manifest/certificate and registers with its own auth token.
7. The fallback file-pairing workflow remains available under `/devices/files`.

Pairing invitations expire after 10 minutes. The server stores only temporary rendezvous state and the encrypted package; the pairing secret is never persisted by the application server.

## One-time prekeys

Each device keeps private one-time ECDH keys locally and publishes only signed public prekey records. The relay verifies the device signature against the current signed manifest before accepting them.

When a sender targets a device, it authenticates and atomically claims one public prekey. After authenticated decryption and local message persistence, the recipient deletes the corresponding private one-time prekey.

If no one-time prekey is available, QuanticMail uses the authorized device's static ECDH key as an explicit compatibility/degraded-security fallback instead of making delivery impossible.

## Crypto V2

Crypto V2 adds a signed public Crypto Profile bound to the existing Quantic identity. The profile can advertise ML-KEM-768 device encryption keys and ML-DSA-65 signing keys.

The protocol supports a transition mode and a `hybrid-required` mode. Once `hybrid-required` is pinned, classical-only delivery cannot silently replace it. Discovery Mesh transports the Crypto Profile together with the signed Identity Manifest and Route Manifest, verifies the P-256 and ML-DSA proofs, checks the canonical profile digest referenced by the Route Manifest, persists the profile in the relay snapshot, and refuses profile removal as a downgrade.

Crypto V2 private material remains on user devices. The relay stores only signed public profiles needed for verification and routing.

## Sent-history sync

A logical outgoing message has one stable message ID. Normal recipient deliveries and encrypted copies sent to the sender's other active devices carry that same logical ID.

A sync copy is transported back to the sender's own canonical identity but retains the external logical recipient inside the encrypted payload. On receipt, it is validated and stored as an **outgoing** message. IndexedDB's message key makes repeated history imports/idempotent sync overwrite the same logical record instead of creating duplicates.

## Standalone Quantic Relay and Discovery Mesh

A standalone relay can be started without Render, GitHub, SMTP or a purchased domain:

```bash
npm run relay:start
```

Runtime variables:

- `QUANTIC_RELAY_HOST`: bind address, default `127.0.0.1`
- `QUANTIC_RELAY_PORT`: listen port, default `8787`
- `QUANTIC_RELAY_DATA_DIR`: durable relay state directory, default `./data`
- `QUANTIC_RELAY_BOOTSTRAP`: optional comma-separated relay origins such as `https://relay-a.example,https://relay-b.example`

An empty `QUANTIC_RELAY_BOOTSTRAP` is valid and creates an isolated/private relay until peers are learned or configured. Bootstrap relays are only entry points: the relay performs a nonce-bound signed Federation hello, derives/verifies the peer `relayId` from its signing key and persists the peer in the normal atomic relay snapshot. A bootstrap endpoint does not sign user identities and is not a directory authority.

Discovery uses namespaced 256-bit keys, XOR distance, bounded Kademlia-style buckets and bounded iterative lookup. Lookups can follow multiple peer paths. Every discovered bundle is cryptographically validated before it can enter trusted local state. Identity, route and Crypto Profile rollback/fork rules remain authoritative over network hints.

`POST /api/quantic/discovery/publish` stores a valid bundle locally and replicates it only to the K closest known peers. Replicated copies carry `replicate:false`, so peers do not create unbounded broadcast loops. `POST /api/quantic/discovery/lookup` performs multi-hop lookup and caches only a valid accepted result.

The acceptance suite launches three independent relay processes with GitHub and Render bootstrap variables removed: relay A knows only C, C knows only B, Bob exists on B, and A discovers Bob through C before Federation delivers the encrypted message to B and returns Bob's delivery receipt to Alice. This proves the tested Discovery/Federation path does not require GitHub or Render once reachable mesh peers are available.

This is not a global-consensus system: network partitions can temporarily expose different reachable records. Cryptographic signatures, monotonic sequences, rollback checks and fork rejection determine what a relay may accept; bootstrap nodes themselves are not trusted as identity authorities.

## Durable standalone relay state

The standalone relay persists its protocol state atomically on disk. The current snapshot includes identity/device relay state, encrypted queues, receipts, signed manifests, one-time-prekey pools and consumed tombstones, Route Manifests, public Crypto Profiles, Federation replay/receipt state and Discovery peers.

Old state formats remain readable through migration logic. Private identity and post-quantum keys are not written into the relay snapshot.

## Optional GitHub manifest checkpoint

The web/Render path can optionally checkpoint signed identity manifests to the repository's `registry` branch.

Runtime configuration:

- `QUANTIC_GITHUB_TOKEN`: GitHub token with permission to read/write repository contents
- `QUANTIC_GITHUB_OWNER`: defaults to `XDSawyerLoL`
- `QUANTIC_GITHUB_REPO`: defaults to `QuanticMail`
- `QUANTIC_GITHUB_BRANCH`: defaults to `registry`

If `QUANTIC_GITHUB_TOKEN` is absent, QuanticMail deliberately reports registry mode as `memory`; it does not pretend durable GitHub persistence is active. A token must be provided through environment variables, never committed to this repository.

Discovery Mesh itself does not require the GitHub registry for peer-to-peer lookup.

## Security boundary and limitations

QuanticMail is an **alpha protocol implementation and has not received an independent security audit**.

P-256 remains the compatibility foundation for legacy identities, certificates and classical fallback. Crypto V2 adds ML-KEM-768 and ML-DSA-65 in a hybrid design rather than replacing every classical primitive at once. Native post-quantum runtime support used by the current implementation is still evolving, so compatibility must be tested on target runtimes.

One-time-prekey forward-secrecy properties are not uniform when static-key fallback is used. The standalone relay persists its public prekey state, while deployment-specific web relay behavior may differ. Discovery Mesh protects the authenticity and monotonicity of discovered records, but it does not provide global consensus or guarantee availability across a network partition.

The root device can authorize/revoke linked devices because it retains the master signing private key. Linked devices do not receive that master private key.

## Legacy mail work

The repository still contains earlier JMAP/Stalwart and Resend experiments for reference. They are no longer the default product direction.

Quantic Network communication between Quantic identities does not require SMTP, MX, IMAP, SPF, DKIM, DMARC, a purchased domain, or a Gmail/Outlook account.
