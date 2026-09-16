# Quantic Network — Federation, Discovery Mesh and Crypto V2

Date: 2026-09-16
Status: design approved in conversation; pending repository review
Base: QuanticMail V1.1 on `main` (`ede6529543031c3c7fba00b0702624ff82c0b9ff`)
Umbrella issue: #11 — Quantic Network V1 — supprimer le point de contrôle unique du relais

## 1. Purpose

Quantic Network must let two Quantic identities exchange encrypted messages without depending on one mandatory relay, Render, GitHub, SMTP/IMAP, Gmail, Outlook, Proton, or any central identity authority.

The existing canonical identity remains the trust root. New identities use the V1.1 128-bit displayed fingerprint form:

```text
handle~0123456789abcdef0123456789abcdef@quantic
```

Legacy 10-hex fingerprints remain valid. Changing relay, transport or cryptographic profile never changes the canonical address.

This design adds three independent but linked layers:

1. **Route Manifest** — where an identity can be reached.
2. **Federation V1** — how one relay forwards an opaque envelope to another relay without sharing device auth tokens.
3. **Crypto Profile V2** — how an identity upgrades from classical P-256 only to hybrid classical + post-quantum cryptography.
4. **Quantic Discovery Mesh** — how relays discover signed Route Manifests without a mandatory global directory.

The layers are deliberately separate from the existing `quantic-identity-manifest` so V1/V1.1 manifests, QR pairing, revocation history, one-time prekeys and existing clients remain readable and upgradeable.

## 2. Existing V1.1 invariants that must not regress

The implementation must preserve these existing properties:

- the canonical identity is derived from the identity master ECDSA P-256 signing key;
- new fingerprints are 32 hex characters, legacy 10-hex fingerprints remain accepted;
- one root device owns identity authorization;
- linked devices have independent ECDH P-256 encryption keys and ECDSA P-256 device-signing keys;
- device authorization/revocation is represented by a monotonically sequenced signed Identity Manifest;
- one-time P-256 prekeys are signed, atomically claimed and never silently reused;
- readable mail remains local-first;
- already encrypted outbox deliveries remain durable client-side and idempotent;
- Quantic relays never receive message plaintext or private identity/device keys.

Federation and Crypto V2 extend these rules; they do not replace them.

## 3. Trust model

### 3.1 Identity remains the root of trust

A relay is never an identity authority. A DHT node is never an identity authority. GitHub is never an identity authority.

A remote object is accepted only if its signature chain terminates in the signing key already bound to the target Quantic canonical address.

For 32-hex identities, the verifier recomputes the SHA-256 fingerprint of the supplied P-256 identity signing public key and requires the canonical address fingerprint to equal the expected 128-bit prefix. Legacy 10-hex identities follow the existing legacy verification rule.

### 3.2 Eventual consistency, not global consensus

Quantic Network does not introduce a blockchain or global consensus ledger.

Signed manifests are monotonic, cached and replicated. Network partitions can temporarily expose different valid historical versions. A node must never accept a manifest older than the highest valid sequence it has already observed for that object.

Immediate global revocation during a complete partition is not claimed. Revocation convergence is bounded by connectivity, cache expiry and successful discovery of a newer signed manifest.

## 4. Route Manifest

### 4.1 Why it is separate

The existing Identity Manifest remains version 1 and unchanged. Adding routing fields directly to it would change canonicalization/signatures and create unnecessary compatibility risk.

Routing therefore uses a separate signed object.

### 4.2 Format

```ts
type QuanticRouteRelay = {
  relayId: string;
  endpoint: string;
  priority: number;
  protocols: string[];
  classicalSigningPublicKey: JsonWebKey;
  postQuantumSigningPublicKeySpki?: string;
  expiresAt: string;
};

type QuanticRouteManifestPayload = {
  version: 1;
  sequence: number;
  canonicalAddress: string;
  identitySigningPublicKey: JsonWebKey;
  identityManifestSequence: number;
  cryptoProfileSequence: number | null;
  cryptoProfileDigest: string | null;
  relays: QuanticRouteRelay[];
  issuedAt: string;
  expiresAt: string;
};

type QuanticRouteManifest = {
  format: "quantic-route-manifest";
  version: 1;
  payload: QuanticRouteManifestPayload;
  signatures: {
    p256: string;
    mlDsa65?: string;
  };
};
```

### 4.3 Canonicalization and signatures

The payload is serialized using one deterministic canonicalization function shared by browser and Node implementations. Relay entries are sorted by `(priority, relayId, endpoint)` before serialization.

The P-256 identity master signing key signs every Route Manifest.

If the current Crypto Profile policy is `hybrid-required`, an ML-DSA-65 signature is also mandatory. A verifier that has already pinned `hybrid-required` must reject a later Route Manifest lacking the ML-DSA signature.

### 4.4 Sequence and expiry

- `sequence` starts at 1 and increases for every routing change.
- A lower sequence than the highest previously accepted sequence is rejected as rollback.
- Same sequence + different canonical payload is a fork and must not be silently resolved.
- Default Route Manifest validity: 30 days.
- Recommended refresh: every 24 hours while the root device is active.
- Expired routes are not used for new sends, but may remain cached as diagnostic history.

### 4.5 Relay identity binding

A route entry does not trust DNS alone. The entry binds an HTTPS endpoint to a persistent relay signing key.

`relayId` is derived from the relay classical signing public key:

```text
relayId = hex(SHA-256(SPKI(P-256 relay signing public key)))
```

The initial implementation may use a shorter display form in UI, but protocol equality uses the full digest.

A relay endpoint must prove possession of that key through the federation handshake before a sender trusts it as the relay identified by the Route Manifest.

## 5. Persistent relay identity and handshake

Each standalone relay generates and durably stores:

- a P-256 relay signing key pair;
- an optional ML-DSA-65 relay signing key pair when Crypto V2 runtime support is enabled;
- its `relayId`;
- a signed relay descriptor containing endpoint, protocol versions and capabilities.

Private relay keys remain on that relay.

New endpoint:

```text
POST /api/quantic/federation/hello
```

Request contains a random caller nonce. Response contains:

```text
relayId
endpoint
protocols
capabilities
nonce
issuedAt
classicalSigningPublicKey
postQuantumSigningPublicKeySpki?
p256Signature
mlDsa65Signature?
```

The nonce prevents replay of a stale proof. The caller verifies `relayId`, the Route Manifest key binding, endpoint normalization and signatures.

## 6. Portable sender proof

### 6.1 Problem solved

Current V1 relay `/send` authenticates an emitting device with a relay-local bearer token. Relay B does not possess Alice's token from relay A and must never receive it.

Federation therefore requires a portable proof generated on Alice's device.

### 6.2 Signed transport envelope

Every federation-capable delivery contains a deterministic sender-authenticated transport envelope.

```ts
type QuanticPortableEnvelope = {
  format: "quantic-envelope";
  version: 2;
  clientMessageId: string;
  from: string;
  fromDeviceId: string;
  to: string;
  toDeviceId: string;
  keyMode:
    | "v1-one-time-prekey"
    | "v1-static-fallback"
    | "hybrid-one-time-prekey"
    | "hybrid-static-fallback";
  cryptoSuite: string;
  preKeyId?: string;
  classicalEphemeralPublicKey?: JsonWebKey;
  pqKemCiphertext?: string;
  iv: string;
  ciphertext: string;
  createdAt: string;
  expiresAt: string;
  signatures: {
    p256Device: string;
    mlDsa65Device?: string;
  };
};
```

The sender signatures cover all fields except the signature values themselves.

Relay A still authenticates Alice locally using her relay auth token before accepting a new send. The token is never embedded in the portable envelope and never leaves A.

Relay B independently verifies the portable envelope against Alice's active device key in a valid Identity Manifest. If Alice has Crypto V2 `hybrid-required`, B also verifies the ML-DSA device signature.

### 6.3 Sender manifest transport

A federation forward packet may carry Alice's current signed Identity Manifest and Crypto Profile as proofs. B verifies them and may cache them.

B rejects an included manifest/profile if it is older than the highest valid sequence B has already seen. If discovery connectivity exists, B should opportunistically query for a newer sequence before accepting security-sensitive state, but lack of a newer reachable record is not by itself proof that the supplied state is newest globally.

## 7. Federation V1

### 7.1 Endpoint

```text
POST /api/quantic/federation/forward
```

The body contains:

```ts
type QuanticFederationForward = {
  format: "quantic-federation-forward";
  version: 1;
  federationId: string;
  originRelay: SignedRelayDescriptor;
  previousRelayId: string;
  hopLimit: number;
  visitedRelayIds: string[];
  expiresAt: string;
  senderIdentityManifest: QuanticIdentityManifest;
  senderCryptoProfile?: QuanticCryptoProfileV2;
  recipientRouteManifest: QuanticRouteManifest;
  envelope: QuanticPortableEnvelope;
  previousRelayAttestation: string;
};
```

### 7.2 Forwarding rules

Default `hopLimit` is 4.

A relay rejects a packet when:

- `federationId` has already been processed and the new packet is not an idempotent retry;
- the relay appears in `visitedRelayIds`;
- `hopLimit <= 0` before local delivery;
- `expiresAt` is in the past;
- the recipient Route Manifest is invalid, expired or rolled back;
- the target relay identity does not match the signed route entry;
- the portable sender proof is invalid;
- the target device is not active according to the accepted recipient Identity Manifest;
- the declared Crypto V2 policy is violated.

A successful retry of the exact same `(federationId, envelope digest)` returns the previously recorded result rather than enqueueing a duplicate.

### 7.3 Local delivery on destination relay

If B is an authorized relay in Bob's current Route Manifest, B stores the opaque envelope in Bob's local device queue.

The existing Bob auth token remains local to B and is only required when Bob pulls/ACKs the message.

Federation metadata is stored separately from the encrypted envelope so the readable client payload and existing envelope semantics remain independent from routing state.

### 7.4 Origin and transit relays

A can forward directly to B when the Route Manifest supplies B.

Transit relays are only needed when B cannot be contacted directly and a configured federation peer can route toward B. Transit relays must not decrypt or rewrite the envelope. They decrement hop count, append their relay ID and sign their forwarding attestation.

Client-direct fallback remains allowed: if A cannot federate but Alice's client can contact B directly, the client may submit the same portable envelope to B through the federation-compatible ingress path.

## 8. Federation receipts

### 8.1 Delivery receipt creation

B does not issue a final delivery receipt merely because it accepted a forwarded envelope. The final receipt is created after Bob's device successfully ACKs that envelope, preserving the current semantic meaning of delivery.

B creates:

```ts
type QuanticFederationReceipt = {
  format: "quantic-federation-receipt";
  version: 1;
  federationId: string;
  clientMessageId: string;
  from: string;
  fromDeviceId: string;
  to: string;
  toDeviceId: string;
  destinationRelayId: string;
  deliveredAt: string;
  recipientRouteSequence: number;
  p256RelaySignature: string;
  mlDsa65RelaySignature?: string;
};
```

### 8.2 Receipt return

B sends the signed receipt directly to the `originRelay` descriptor carried in the federation packet.

New endpoint:

```text
POST /api/quantic/federation/receipt
```

A verifies:

- the destination relay signature;
- that the destination relay was authorized by the recipient Route Manifest sequence referenced by the receipt;
- message/federation IDs;
- anti-replay state.

A then translates the verified federation receipt into the existing sender-device receipt queue used by Alice.

If A is offline, B keeps the federation receipt durably and retries. Receipt expiry follows the existing message TTL unless a later protocol version changes it.

## 9. Crypto Profile V2

### 9.1 Standards

Quantic Crypto V2 uses:

- ML-KEM-768 from NIST FIPS 203 for post-quantum key establishment;
- ML-DSA-65 from NIST FIPS 204 for post-quantum signatures;
- existing ECDH/ECDSA P-256 as the classical component during hybrid migration;
- HKDF-SHA-256 as the explicit Quantic hybrid secret combiner;
- AES-256-GCM as the message AEAD.

Quantic does not claim that its complete protocol is NIST-certified merely because the primitives are standardized.

The implementation must use runtime/platform cryptographic primitives. It must not ship a hand-written lattice implementation.

### 9.2 Public key encoding

PQC public keys in protocol documents are encoded as base64url SubjectPublicKeyInfo (SPKI) bytes, with an explicit algorithm name.

Private PQC material remains local and is serialized only in a runtime-supported private-key format suitable for encrypted/local storage. It is never transmitted to a relay or registry.

### 9.3 Profile format

```ts
type QuanticCryptoDeviceV2 = {
  deviceId: string;
  mlKemAlgorithm: "ML-KEM-768";
  mlKemPublicKeySpki: string;
  mlDsaAlgorithm: "ML-DSA-65";
  mlDsaPublicKeySpki: string;
};

type QuanticCryptoProfileV2 = {
  format: "quantic-crypto-profile";
  version: 2;
  payload: {
    version: 2;
    sequence: number;
    canonicalAddress: string;
    identitySigningPublicKey: JsonWebKey;
    identityManifestSequence: number;
    policy: "transition" | "hybrid-required";
    identityMlDsaAlgorithm: "ML-DSA-65";
    identityMlDsaPublicKeySpki: string;
    devices: QuanticCryptoDeviceV2[];
    issuedAt: string;
  };
  signatures: {
    p256: string;
    mlDsa65Self: string;
    mlDsa65Continuity?: string;
  };
};
```

### 9.4 Activation and continuity

The first Crypto V2 profile requires:

- a valid P-256 identity master signature;
- a valid ML-DSA-65 self-signature proving possession of the new PQ identity private key.

Subsequent profiles require the P-256 signature plus continuity from the previously accepted ML-DSA identity key.

If the ML-DSA identity key is rotated, the update must be signed by the previous valid ML-DSA key and include a self-signature by the new key. A verifier must never accept a new unrelated ML-DSA root solely because it carries a P-256 signature after Crypto V2 has already been pinned.

This makes later compromise of only the classical identity key insufficient to silently erase or replace an already established PQ trust root.

### 9.5 Device upgrade

Each active device generates its own ML-KEM-768 and ML-DSA-65 key pairs locally.

A linked device proves its proposed PQ public keys using:

- its existing P-256 device signing key from the Identity Manifest;
- an ML-DSA self-signature from the proposed PQ device signing key.

The root verifies the request and publishes the keys in a new Crypto Profile sequence.

No PQ device private key is transferred to the root.

## 10. Hybrid message encryption

### 10.1 Quantic suite identifier

Initial suite:

```text
QNT-HYB-P256-MLKEM768-HKDFSHA256-AES256GCM-1
```

This explicit Quantic suite name prevents runtime-specific WebCrypto naming changes from becoming wire-format changes.

### 10.2 Shared secret combination

For a hybrid delivery, the sender obtains:

- `classicalSecret`: 32-byte ECDH P-256 shared secret;
- `pqSecret`: 32-byte ML-KEM-768 encapsulated shared secret.

The secrets are combined in fixed order:

```text
IKM = classicalSecret || pqSecret
salt = SHA-256("quantic-hybrid-kdf-v1")
info = UTF8(canonical context)
messageKey = HKDF-SHA-256(IKM, salt, info, 32 bytes)
```

The canonical context contains at minimum:

```text
suite
from
fromDeviceId
to
toDeviceId
clientMessageId
keyMode
preKeyId-or-empty
```

The resulting 32-byte key is used only for AES-256-GCM encryption of that delivery.

Any later change to this combiner requires a new suite identifier.

### 10.3 Hybrid one-time prekeys

Crypto V2 extends, rather than removes, V1.1 one-time prekeys.

A V2 one-time prekey bundle contains:

- the existing one-time ECDH P-256 public key;
- a one-time ML-KEM-768 public key;
- one `preKeyId` binding both components;
- creation/expiry metadata;
- P-256 device signature;
- ML-DSA-65 device signature when policy requires it.

The relay claims the bundle atomically. The recipient deletes both private one-time components only after authenticated decryption, semantic validation and durable local persistence succeed.

### 10.4 Static hybrid fallback

For availability, a V2 device also has long-term ML-KEM and classical P-256 device public keys. If the one-time pool is empty, the protocol may use `hybrid-static-fallback` unless a future stricter user policy disables static fallback.

Static fallback remains hybrid post-quantum/classical but does not claim the same forward-secrecy properties as one-time hybrid prekeys.

## 11. Signatures and downgrade resistance

### 11.1 Message signatures

Portable envelopes are signed by the sender device using ECDSA P-256.

If the sender's accepted Crypto Profile is `hybrid-required`, ML-DSA-65 device signature is mandatory as well.

### 11.2 Anti-downgrade pin

Clients persist per-contact security state:

```text
highestIdentityManifestSequence
highestCryptoProfileSequence
strongestCryptoPolicySeen
identityMlDsaKeyDigest
highestRouteManifestSequence
```

Once `hybrid-required` has been accepted for a canonical identity, the client must not silently send that identity a V1-only delivery because a later lookup omits, hides or rolls back the Crypto Profile.

Instead the send fails with an explicit compatibility/security error.

Resetting such a security pin is an explicit user action and must never happen as automatic failover.

### 11.3 Transition mode

`policy: "transition"` exists only to upgrade an identity whose active devices are not all PQ-capable yet.

During transition:

- PQ-capable devices should receive hybrid deliveries;
- legacy devices may still receive V1.1 deliveries;
- all profile updates still require ML-DSA continuity after the initial profile;
- moving from `hybrid-required` back to `transition` is forbidden.

When every active device in the current Identity Manifest has a matching PQ entry, the root may advance the profile to `hybrid-required`.

## 12. Quantic Discovery Mesh

### 12.1 Scope

The Discovery Mesh distributes signed public routing records. It does not transport message plaintext and does not become the mailbox store.

Initial mesh participation is implemented by standalone relays. Browser clients query their configured relays. The embedded Next.js relay may consume discovery through configured peers but does not need to host a full DHT node in the first implementation.

### 12.2 DHT model

Use a Kademlia-style DHT operated by Quantic relays.

Lookup key:

```text
SHA-256("quantic-route:" + lowercaseCanonicalAddress)
```

Stored value: the complete signed `QuanticRouteManifest`.

Replication is targeted to the DHT nodes closest to the lookup key; no relay is required to keep a full global directory.

### 12.3 Record acceptance

A discovery node may store or forward a record only after basic structural checks. A consuming relay/client performs full cryptographic verification before using it.

Rules:

- invalid signature: reject;
- expired manifest: do not return as current;
- lower sequence than local highest: reject as rollback;
- same sequence + different canonical payload: mark fork, retain evidence, query additional paths;
- higher valid sequence: accept and cache.

### 12.4 Parallel lookup

A route lookup uses multiple independent paths rather than trusting one peer.

Initial policy:

- three independent lookup paths;
- peer diversity when possible;
- bounded query fanout;
- hard timeout per lookup;
- positive and negative cache TTLs;
- rotate peers after repeated inconsistent or failing responses.

Signatures protect integrity. Multi-path lookup improves availability against malicious/failed peers but does not claim complete Sybil/Eclipse resistance.

### 12.5 Bootstrap

A fresh relay needs at least one reachable peer or configured route into the mesh. There is no physically meaningful zero-knowledge discovery without any contact point.

Supported bootstrap sources:

- peers already stored from earlier runs;
- user-configured relays/peers;
- optional Quantic-maintained bootstrap list;
- invite/QR-provided peers;
- later LAN/local discovery.

Official bootstrap peers are convenience, not authority. The user may remove all official peers and use only self-controlled peers.

### 12.6 No GitHub dependency

GitHub registry checkpoints may remain as an optional compatibility/bootstrap source, but normal federation/discovery must not require GitHub.

The network acceptance test explicitly runs with GitHub access disabled.

## 13. Relay discovery/federation state

The standalone durable relay snapshot is extended with versioned state for:

- Route Manifests;
- Crypto Profiles;
- relay descriptors/peer table;
- DHT routing metadata needed for restart recovery;
- highest-sequence pins;
- processed `federationId` records;
- federation delivery metadata;
- pending federation receipts;
- relay identity keys or protected references to them.

Existing identities, queues, receipts, prekeys and send windows remain preserved.

Snapshot migration must be explicit and tested. A current valid V1/V1.1 relay state file must upgrade without data loss.

## 14. Privacy and metadata

Federation relays still must not receive message plaintext.

Relays can observe unavoidable transport metadata including some combination of:

- sender/recipient canonical identities;
- sender/recipient device IDs;
- relay path;
- message size;
- timing;
- route lookup keys;
- delivery/receipt timing.

The first federation version does not claim metadata anonymity, onion routing or traffic-analysis resistance.

A future privacy layer can change discovery/routing exposure without changing canonical identity addresses.

## 15. Failure handling

### 15.1 Destination relay unavailable

Origin relay tries recipient relays in signed priority order. Network errors, retryable 5xx/408/425/429 and failed relay handshake may advance to the next authorized relay.

Cryptographic/authentication failures never trigger blind fallback to a weaker security mode.

### 15.2 Route lookup unavailable

If a valid non-expired route exists in cache, use it.

Otherwise the client's durable outbox keeps the already encrypted logical delivery pending and discovery retries later. The message is not marked sent/delivered until transport acceptance/receipt semantics succeed.

### 15.3 Discovery fork

A same-sequence conflicting signed record is treated as a security event, not “last write wins.”

The resolver queries additional independent peers, retains both candidates for diagnostics and refuses automated routing when it cannot establish a non-conflicting latest record.

### 15.4 Crypto capability unavailable

If recipient policy is `hybrid-required` and the local runtime cannot perform the required suite, sending stops with an explicit compatibility error.

No automatic classical downgrade is permitted.

## 16. Runtime strategy

Server-side PQC baseline: Node runtime with native ML-KEM-768 and ML-DSA-65 support.

Browser-side Crypto V2 is capability-detected. Quantic Glide/Chromium builds can enable PQC when the required WebCrypto operations are available. Browsers without required primitives remain V1.1-capable but cannot send to contacts pinned `hybrid-required`.

The wire protocol uses Quantic suite identifiers and SPKI key encoding so it is not tied to one browser vendor's temporary API naming.

Relevant standards/runtime references:

- NIST FIPS 203 — ML-KEM: https://csrc.nist.gov/pubs/fips/203/final
- NIST FIPS 204 — ML-DSA: https://csrc.nist.gov/pubs/fips/204/final
- Node WebCrypto documentation (ML-KEM/ML-DSA support): https://nodejs.org/api/webcrypto.html
- WICG Modern Algorithms in Web Crypto proposal: https://wicg.github.io/webcrypto-modern-algos/

## 17. API surface introduced by this design

Expected endpoints, subject to exact module placement during implementation:

```text
GET/POST /api/quantic/route-manifest
GET/POST /api/quantic/crypto-profile
POST     /api/quantic/federation/hello
POST     /api/quantic/federation/forward
POST     /api/quantic/federation/receipt
GET      /api/quantic/federation/status
```

Standalone discovery also exposes an internal peer/discovery adapter; browser clients do not directly manipulate DHT records in the initial version.

Existing V1 endpoints stay functional.

## 18. Implementation boundaries

This design is one architecture but implementation should be staged in reviewable tranches:

### Tranche A — signed routing + explicit federation

- Route Manifest types/canonicalization/signatures/state;
- persistent relay identity and hello handshake;
- portable sender-signed envelope;
- A -> B forwarding using an explicitly known signed Route Manifest;
- destination ACK -> signed federation receipt -> origin receipt queue;
- durable federation metadata;
- no DHT requirement yet.

### Tranche B — distributed discovery

- peer table and bootstrap;
- Kademlia discovery adapter;
- signed Route Manifest publication/lookup;
- sequence/fork/cache rules;
- three-path lookup;
- restart persistence;
- Render/GitHub-off discovery test.

### Tranche C — Crypto V2

- PQC capability adapter;
- Crypto Profile V2 activation/continuity;
- per-device ML-KEM/ML-DSA upgrade;
- hybrid one-time prekey bundles;
- hybrid encryption suite;
- dual message/manifest signatures;
- anti-downgrade pins;
- transition -> hybrid-required migration tests.

The order may overlap where tests require shared abstractions, but each tranche must remain independently reviewable and must keep `main` green.

## 19. Security test requirements

Tests must cover at least:

- Route Manifest deterministic canonicalization;
- route signature tamper rejection;
- route rollback rejection;
- route same-sequence fork detection;
- relay ID/key mismatch rejection;
- relay hello nonce replay rejection;
- portable envelope signature tamper rejection;
- sender device revoked -> federation rejected;
- sender auth token never appears in federation packet/state/log fixtures;
- hop limit and loop rejection;
- federation idempotent retry;
- duplicate federation packet does not duplicate recipient queue;
- destination ACK creates exactly one federation receipt;
- forged destination receipt rejected;
- recipient route sequence mismatch rejected;
- restart recovery of pending forwards/receipts;
- DHT invalid record rejection;
- DHT stale record rejection after higher sequence pin;
- DHT conflicting same-sequence record produces fork state;
- lookup succeeds through independent peers when one path lies or fails;
- operation succeeds with Render and GitHub disabled when A/B and mesh peers are reachable;
- Crypto Profile activation requires classical + PQ proof;
- PQ root replacement without continuity rejected;
- `hybrid-required` downgrade rejected;
- hybrid encryption round trip;
- tampering with P-256 component, ML-KEM component, KDF context, IV or ciphertext fails;
- claimed hybrid prekey cannot be reused;
- static hybrid fallback is explicitly identified and never mislabeled one-time;
- legacy V1.1 sender/recipient behavior remains unchanged when federation/PQC is not negotiated.

## 20. Acceptance scenarios

### 20.1 Federation without common relay

- Alice is registered only on relay A.
- Bob is registered only on relay B.
- A has Bob's valid Route Manifest.
- Alice sends through A.
- A forwards to B without Alice's auth token leaving A.
- Bob pulls and decrypts on B.
- Bob ACKs.
- B sends a signed federation receipt to A.
- Alice receives the normal delivery receipt from A.

### 20.2 No Render / no GitHub

- Render is unreachable.
- GitHub registry is unreachable.
- standalone relays A and B restart from durable local state.
- mesh peers are reachable through stored/user bootstrap peers.
- A resolves Bob's signed Route Manifest through the Discovery Mesh.
- Alice -> A -> B -> Bob succeeds.
- receipt B -> A -> Alice succeeds.

### 20.3 Post-quantum required

- Bob's latest Crypto Profile is pinned `hybrid-required`.
- Bob's target device has ML-KEM-768/ML-DSA-65 keys.
- Alice's runtime supports the Quantic hybrid suite.
- delivery uses hybrid key establishment and dual signatures.
- a resolver that hides Bob's Crypto Profile cannot force a V1-only send because Alice's local security pin remembers `hybrid-required`.

### 20.4 Incompatible client

- Bob requires Crypto V2.
- Alice's browser lacks required PQ primitives.
- the client refuses to send and reports that Bob requires post-quantum protection.
- it does not silently downgrade.

## 21. Non-goals for this tranche

This design does not yet provide:

- Tor/onion routing;
- anonymous metadata-resistant addressing;
- NAT-traversed direct browser-to-browser transport;
- global consensus or blockchain identity;
- formal cryptographic proof;
- third-party security audit;
- automatic recovery from compromise of the identity root private keys;
- SMTP/IMAP interoperability for `@quantic` identities.

Direct device-to-device transport remains a later Quantic Network step. The routing, identity and Crypto Profile objects defined here should be reusable by that future transport.

## 22. Architectural outcome

After all three implementation tranches, the normal Quantic message path is:

```text
Quantic Identity
    |
    +-- Identity Manifest V1/V1.1
    +-- Crypto Profile V2
    +-- Route Manifest
            |
            v
    Quantic Discovery Mesh
            |
        Relay A  ----------------->  Relay B
          |         Federation          |
        Alice                          Bob
```

Render, GitHub and official bootstrap nodes may all be absent from the active message path once relays have alternative reachable peers/routes.

The identity remains user-owned, the message remains end-to-end encrypted, relay selection remains replaceable, and the network can migrate to hybrid post-quantum protection without changing users' canonical Quantic addresses.
