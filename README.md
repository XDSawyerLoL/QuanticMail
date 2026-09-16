# QuanticMail

QuanticMail is the local-first messaging product of Quantic Sillage.

QuanticMail is not designed around Gmail-style hosted mailboxes or SMTP as its core transport. The product uses its own Quantic Network identities such as `sansa@quantic`, with a self-certifying canonical identity such as `sansa~4f82a19c2d@quantic`.

## V0.8 architecture

- **Human identity:** `name@quantic`
- **Canonical identity:** `name~fingerprint@quantic`, derived from the identity signing key
- **Client:** Next.js / React / TypeScript
- **Device crypto:** Web Crypto, ECDH P-256 + AES-256-GCM for messages
- **Identity proof:** ECDSA P-256 proof-of-possession challenges
- **Local mailbox:** browser IndexedDB
- **Trusted contacts:** first-seen public keys are pinned locally
- **Durable local outbox:** encrypted messages stay on the sender device until delivery is acknowledged
- **Identity recovery:** password-encrypted `.quantic-vault` file using PBKDF2-SHA-256 + AES-256-GCM
- **Directory and relay:** Render
- **Readable message storage:** user device
- **Relay storage:** encrypted envelopes only

The private identity keys stay on the user's device unless the user explicitly exports an encrypted Quantic Identity Vault. Render never receives the vault password or private keys.

## Current deployment

- **Web application:** `https://quanticmail.onrender.com`
- **Identity Vault:** `https://quanticmail.onrender.com/vault`
- **Network:** Quantic Network V0.7 protocol + V0.8 recovery layer

## V0.8 capabilities

- create a human-readable `@quantic` identity
- derive a self-certifying canonical identity from a signing-key fingerprint
- prove canonical identity ownership with a signed server challenge
- recover the same canonical identity after a relay restart
- encrypt Quantic messages in the browser
- keep an encrypted local outbox until a delivery receipt returns
- retry queued messages after network or relay interruptions
- pin known contact keys locally and block silent key changes
- export the identity into a password-encrypted `.quantic-vault` file
- restore that identity on a fresh browser/device with a new local auth token
- keep vault encryption and decryption entirely client-side

See [`docs/V0.8-IDENTITY-VAULT.md`](docs/V0.8-IDENTITY-VAULT.md).

## What the vault contains

The V0.8 vault contains the encryption private key and the identity-signing private key, together with the matching public keys and the human handle. It does **not** contain the mailbox, contacts, sent messages, received messages, or the current Render authentication token.

When a vault is restored, QuanticMail generates a fresh device token. The restored signing private key then proves ownership of the canonical identity through the V0.7 challenge flow.

## Zero-cost durability model

Render Free web services use ephemeral local storage. QuanticMail therefore does not treat the Render process as the durable source of truth for message delivery or identity ownership. Message durability comes from the encrypted sender outbox; identity continuity comes from the user's self-certifying signing key and optional encrypted vault file.

A Render restart can still clear temporary directory, relay and receipt state. Active clients can re-register their canonical identities and retry pending envelopes without changing their cryptographic identity.

## Recovery boundary

Quantic Sillage does not retain a copy of the user's private keys or vault password. Losing both the local identity and every exported vault makes that canonical identity unrecoverable by design.

## Legacy mail work

The repository still contains the earlier JMAP/Stalwart and Resend experiments for reference. They are no longer the default product direction.

Quantic Network does not require SMTP, MX, IMAP, SPF, DKIM, DMARC, a purchased domain, or a Gmail/Outlook account for communication between Quantic identities.
