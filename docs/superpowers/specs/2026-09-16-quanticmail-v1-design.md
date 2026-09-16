# QuanticMail V1.0 Protocol Design

## Goal

Turn the V0.9 multi-device prototype into a defensible V1.0 protocol under the existing constraints: no paid infrastructure requirement, Render remains the public relay, readable content stays on user devices, and identity ownership remains cryptographic rather than account-provider based.

## Non-negotiable constraints

- Human addresses remain `name@quantic`.
- Canonical identities remain `name~fingerprint@quantic` and are derived from the root ECDSA P-256 signing key.
- Private root keys never leave the user's device except inside an explicitly exported encrypted Identity Vault.
- Linked devices have independent encryption/signing key pairs and never receive the root signing private key.
- Message plaintext is never stored by Render.
- The system must continue to function when no durable registry backend is configured.
- No paid Render disk or expiring Render Postgres instance is required.
- GitHub registry persistence is optional and additive; runtime messaging must not depend on GitHub availability.

## Scope

V1.0 contains four protocol upgrades:

1. **Signed identity manifests** — one signed document represents the currently authorized devices and revocations for a canonical identity.
2. **Anti-rollback state** — clients persist the highest manifest version they have observed and reject older manifests.
3. **Device revocation** — the root device can publish a new signed manifest that removes a linked device and records a signed revocation event.
4. **Optional durable GitHub checkpoint** — Render can mirror signed manifests into a GitHub-backed registry when explicitly configured with a server-side token. GitHub is a durable checkpoint, not the transport path.

The existing V0.9 fan-out message encryption remains. V1.0 does not attempt a full Signal-style double ratchet, persistent plaintext history synchronization, or anonymous spam-proof global discovery. Those are separate protocol projects.

## Architecture

### 1. Signed manifest

Each canonical identity has a `QuanticIdentityManifest`:

```ts
type QuanticManifestDevice = {
  deviceId: string;
  label: string;
  publicKey: JsonWebKey;
  deviceSigningPublicKey: JsonWebKey;
  kind: "root" | "linked";
  issuedAt: string;
};

type QuanticRevocation = {
  deviceId: string;
  revokedAt: string;
  reason: "user" | "lost" | "compromised" | "replaced";
};

type QuanticIdentityManifestPayload = {
  version: 1;
  sequence: number;
  canonicalAddress: string;
  handle: string;
  fingerprint: string;
  identityPublicKey: JsonWebKey;
  identitySigningPublicKey: JsonWebKey;
  devices: QuanticManifestDevice[];
  revocations: QuanticRevocation[];
  issuedAt: string;
};

type QuanticIdentityManifest = {
  format: "quantic-identity-manifest";
  version: 1;
  payload: QuanticIdentityManifestPayload;
  signature: string;
};
```

The signature is ECDSA P-256/SHA-256 over a deterministic canonical text representation. `sequence` is strictly increasing. A manifest is accepted only when:

- the root signing-key fingerprint matches the canonical address;
- the signature verifies;
- device IDs match their encryption public keys;
- no device appears both active and revoked;
- there is exactly one root device;
- the incoming sequence is not lower than the highest sequence known locally or by the relay.

### 2. Relay state

Render keeps an in-memory cache of the latest verified manifest for each canonical identity. The existing identity/device maps are derived from that manifest instead of being the source of truth.

On relay restart:

- active clients can republish their latest signed manifest;
- if a durable registry backend is configured, Render first attempts to load the latest signed manifest from that backend;
- if the backend is unavailable, Render continues in local-first mode.

### 3. Durable registry adapter

Introduce a `RegistryStore` interface:

```ts
interface RegistryStore {
  load(canonicalAddress: string): Promise<QuanticIdentityManifest | null>;
  save(manifest: QuanticIdentityManifest): Promise<void>;
}
```

Implementations:

- `MemoryRegistryStore` — always available, process-local.
- `GitHubRegistryStore` — optional durable checkpoint using environment variables:
  - `QUANTIC_GITHUB_TOKEN`
  - `QUANTIC_GITHUB_OWNER`
  - `QUANTIC_GITHUB_REPO`
  - `QUANTIC_GITHUB_BRANCH` (default `registry`)

GitHub paths use a deterministic hash of the canonical address to avoid unsafe filenames:

`registry/identities/<sha256(canonicalAddress)>.json`

Writes use the GitHub Contents API with optimistic SHA replacement. The signed manifest itself remains authoritative; GitHub cannot forge a valid state without the root private key.

### 4. Revocation

Only a root device holding the root signing private key can create a later manifest that removes a device. Revocation is represented both by absence from `devices` and presence in `revocations`.

A revoked device fails authentication as soon as the relay has observed the later manifest. Clients that have seen sequence N reject a rollback to N-1 even if a stale relay tries to serve it.

Because a free, unconfigured relay has no durable memory, perfect global revocation after every participant goes offline is impossible without a durable checkpoint. V1.0 states this explicitly rather than pretending otherwise.

### 5. Contact trust

Local contacts stop pinning only a single encryption key. They pin:

- canonical identity fingerprint;
- highest manifest sequence seen;
- root signing public key.

Device encryption keys may change as the signed manifest evolves without triggering a false identity-change warning.

### 6. Sending

Send flow:

1. Resolve recipient identity.
2. Verify latest signed manifest.
3. Reject manifest rollback relative to local contact state.
4. Encrypt the same plaintext payload independently for every active device.
5. Store every encrypted device envelope in the durable local outbox.
6. Remove each outbox envelope only after its device-specific delivery receipt arrives.

### 7. Pairing

The existing `.quantic-device-request` / `.quantic-device-cert` flow remains compatible. Root approval additionally advances and signs the identity manifest. V1.0 will expose revocation from `/devices`.

QR pairing is intentionally deferred: it improves UX but does not improve the protocol's correctness. File-based pairing remains the reliable baseline for V1.0.

## API changes

Add:

- `GET /api/quantic/manifest?handle=<locator>` — latest verified signed manifest.
- `POST /api/quantic/manifest` — publish a later signed manifest.
- `POST /api/quantic/devices/revoke` — convenience endpoint accepting a fully signed later manifest; server still validates the manifest rather than trusting the requested device ID.
- `GET /api/quantic/registry/status` — reports `memory` or `github` backend without exposing credentials.

Existing resolve/send/pull/ack/receipt routes continue to work.

## Error handling

Protocol-level errors use explicit status codes:

- `400` malformed manifest/device/key
- `401` invalid signature or device authentication
- `404` unknown canonical identity
- `409` ambiguous short handle or manifest sequence rollback/conflict
- `428` proof/certificate/manifest required
- `429` rate limit
- `503` optional durable registry unavailable when an operation explicitly requires checkpointing

A GitHub checkpoint failure never causes plaintext loss and never invalidates a locally valid signed manifest. The relay may report degraded durability while continuing real-time transport.

## Testing

V1.0 adds a protocol test suite before production changes. Tests cover:

- deterministic canonical manifest serialization;
- valid signature acceptance;
- rejection of wrong root key/fingerprint;
- rejection of sequence rollback;
- revocation removes device authorization;
- stale device certificate cannot reactivate a revoked device when a newer manifest is known;
- fan-out targets only active devices;
- registry adapter path generation is deterministic and safe.

CI order becomes `npm test`, `npm run build`, `npm run lint`, then existing deployment validations.

## Security boundary

V1.0 improves identity continuity and revocation, but it is not a claim of perfect decentralization or post-compromise forward secrecy. A malicious transport can still observe metadata and deny service. A compromised active device can read messages encrypted for that device until revoked. The optional GitHub registry improves durable anti-rollback/revocation but introduces GitHub as a storage dependency for that checkpoint only.

## Definition of done

V1.0 is ready when:

- CI has automated protocol tests and all are green;
- root devices can revoke linked devices;
- clients reject signed-manifest rollback;
- routing uses active devices from the latest signed manifest;
- the system works with memory-only registry;
- an optional GitHub registry adapter is implemented and safely disabled when credentials are absent;
- `/devices` shows active/revoked state and allows root revocation;
- README and protocol documentation clearly state durability guarantees and limits;
- Render production build is live and healthy.
