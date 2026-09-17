# Quantic Network V1.3 — Stabilization, Decentralized Resolution and Core Extraction

## Goal

Turn the current QuanticMail-hosted network stack into a safer Quantic Network V1.3 foundation that can be consumed by QuanticMail and later by Quantic Glide, Quantic OS and Providence, while preserving the existing local-first and hybrid post-quantum security model.

## Non-negotiable security invariants

- Readable message bodies and private identity/device/PQ keys remain on user devices.
- Relay and Discovery traffic carries ciphertext plus the minimum routing metadata required by the protocol.
- Existing P-256 identity continuity, device revocation, one-time-prekey rules, Crypto Profile V2 verification and `hybrid-required` anti-downgrade rules remain authoritative.
- A direct device-to-device path transports the already encrypted Quantic envelope; it must never decrypt, re-encrypt, or silently downgrade the envelope.
- Short `name@quantic` handles are convenience aliases. The canonical `name~fingerprint@quantic` identity remains the cryptographic authority.
- Ambiguous short handles must fail closed with an explicit conflict instead of silently selecting an identity.
- Direct transport is opportunistic. Store-and-forward relay/federation delivery remains the mandatory fallback.
- Network hints (bootstrap endpoints, peer hints, signaling messages) are never identity authorities.

## 1. Discovery-first short-handle resolution

Discovery Mesh gains a deterministic handle key in addition to canonical identity keys. The same signed Discovery bundle is indexed under both keys; no unsigned alias record becomes authoritative.

A relay resolving `name@quantic` follows this order:

1. live/local relay identity state;
2. locally pinned signed manifests;
3. Discovery handle lookup across bounded independent paths;
4. optional legacy GitHub checkpoint only on the Next compatibility path;
5. `404` when no valid identity exists, or `409` when multiple distinct canonical identities validly claim the same short handle.

Discovery handle lookup must verify the existing Identity Manifest, Route Manifest and optional Crypto Profile exactly as canonical lookup does. A valid signed bundle whose manifest handle differs from the requested handle is ignored.

## 2. Quantic Network boundary

Introduce a public Quantic Network facade under `lib/quantic-network/`. QuanticMail keeps its UI in this repository but consumes stable exported network primitives instead of being the conceptual owner of the protocol.

The first facade covers:

- identity addressing and handle normalization;
- relay endpoint policy and bootstrap selection;
- direct-transport wire types;
- app capability / Quantic Core identity types.

Existing `lib/quantic/*` modules remain compatible during V1.3. This is an extraction seam, not a destructive repository move.

## 3. Multi-bootstrap defaults

The client must not treat one hosted relay as the only bootstrap. Default relay configuration supports a bounded list supplied by `NEXT_PUBLIC_QUANTIC_BOOTSTRAPS`, plus the existing public relay for compatibility and same-origin fallback.

Rules:

- deduplicate by normalized origin;
- HTTPS for remote relays; HTTP only for localhost;
- retain user-configured relays and active-relay affinity;
- a dead seed is skipped by existing failover;
- user configuration always remains local.

The standalone relay already accepts comma-separated `QUANTIC_RELAY_BOOTSTRAP`; V1.3 documents and validates multiple entries consistently.

## 4. Relay hardening

### PostgreSQL consistency

PostgreSQL persistence gains optimistic revision control. Concurrent relay processes may not silently overwrite a newer snapshot. A stale writer receives an explicit conflict instead of corrupting state.

### Relay identity at rest

When `QUANTIC_RELAY_IDENTITY_SECRET` is provided, the relay signing private key stored in PostgreSQL is encrypted with AES-256-GCM using a scrypt-derived key and per-record random salt/IV. Existing plaintext identity rows remain readable for migration and are rewritten encrypted when the secret is configured.

### HTTP and abuse controls

- enforce request, header and keep-alive timeouts on the standalone HTTP server;
- bound direct-signaling payloads, queue sizes and TTLs;
- authenticate signaling operations to an existing registered device;
- do not expose private keys in diagnostics;
- preserve existing 512 KiB request limits for protocol routes.

## 5. Opportunistic direct device transport

V1.3 introduces a WebRTC DataChannel transport using relay-assisted signaling.

The signaling relay is only a rendezvous:

- authenticated devices can announce/poll signaling messages for their own canonical identity and device ID;
- offers/answers/ICE candidates are short-lived and bounded;
- the relay never receives readable message content through signaling;
- DataChannel application frames contain the same encrypted Quantic relay envelope and delivery receipt semantics.

The browser transport attempts direct delivery only when the platform provides `RTCPeerConnection` and the recipient can establish a session promptly. Failure, timeout, unsupported browsers, NAT/firewall failure, or peer absence falls back to the normal relay request without losing the durable outbox item.

The direct layer is an optimization, not a new trust boundary: envelope cryptography and Crypto V2 policy remain unchanged.

## 6. Quantic Core app capabilities

A Quantic identity can authorize product-scoped application keys without copying the master identity private key into every Quantic product.

A `quantic-app-capability` contains:

- canonical Quantic identity;
- application identifier (`mail`, `glide`, `os`, `providence`, or another validated slug);
- app-specific public signing key;
- requested scopes;
- issued/expiry timestamps;
- random nonce;
- root identity signature.

Capabilities are independently verifiable against the signed Identity Manifest. Expired capabilities, wrong canonical identities, unknown scopes supplied by a consumer, or invalid root signatures fail closed. Each product can therefore reuse Quantic Identity while keeping separate app keys.

## Compatibility

- Existing V1.2 identities, legacy 10-hex fingerprints and 32-hex identities remain valid.
- Existing relay HTTP routes stay available.
- GitHub checkpoint support remains optional compatibility infrastructure, not a required Discovery authority.
- JMAP/Stalwart legacy code is untouched by the network protocol work.
- No mandatory new third-party browser dependency is introduced; WebRTC uses platform APIs.

## Acceptance tests

V1.3 is accepted only when CI proves:

1. unique short handle resolves through Discovery after local relay identity state is absent;
2. two valid canonical identities with the same handle return ambiguity;
3. handle lookup rejects malformed/unsigned/forked/downgraded bundles;
4. multiple default bootstrap endpoints are normalized, deduplicated and failed over;
5. PostgreSQL stale snapshot writes are rejected;
6. encrypted PostgreSQL relay identity can round-trip and detect a wrong secret;
7. direct signaling rejects unauthenticated or cross-device polling and expires old messages;
8. direct wire frames preserve encrypted-envelope fields without a plaintext body field;
9. app capabilities verify against the identity root key and reject tampering/expiry;
10. existing full tests, Next production build, ESLint and standalone relay smoke all remain green.
