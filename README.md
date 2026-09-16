# QuanticMail

QuanticMail is the local-first messaging product of Quantic Sillage.

QuanticMail is not designed around Gmail-style hosted mailboxes or SMTP as its core transport. The product uses its own Quantic Network identities such as `vnhz@quantic`.

## V0.6 architecture

- **Identity:** human-readable `name@quantic`
- **Client:** Next.js / React / TypeScript
- **Device crypto:** Web Crypto, ECDH P-256 + AES-256-GCM
- **Local mailbox:** browser IndexedDB
- **Trusted contacts:** first-seen public keys are pinned locally
- **Durable local outbox:** encrypted messages stay on the sender device until delivery is acknowledged
- **Directory and relay:** Render
- **Readable message storage:** user device
- **Relay storage:** encrypted envelopes only

The private identity key stays on the user's device. Render receives routing metadata and ciphertext, not plaintext message content.

## Current deployment

- **Web application:** `https://quanticmail.onrender.com`
- **Network:** Quantic Network V0.6 alpha

## V0.6 alpha capabilities

- create and reserve a `@quantic` identity
- generate identity encryption keys locally
- resolve another Quantic identity
- pin a known contact's public key locally and block silent key changes
- encrypt messages in the browser before sending
- keep an encrypted local outbox until a delivery receipt returns
- automatically retry queued messages after network or relay interruptions
- deduplicate repeated relay submissions
- receive and decrypt messages on the recipient device
- generate a delivery receipt only after local recipient persistence succeeds
- store readable sent and received messages in IndexedDB
- automatic polling plus manual synchronization

See [`docs/V0.6-DURABLE-DELIVERY.md`](docs/V0.6-DURABLE-DELIVERY.md).

## Zero-cost durability model

Render Free web services use ephemeral local storage. QuanticMail therefore does not treat the Render process as the durable source of truth for message delivery. The sender device retains the encrypted envelope and retries it until the recipient has persisted the plaintext locally and the sender receives the resulting delivery receipt.

A Render restart can still clear the temporary directory/relay state and current handle reservations. It should no longer, by itself, permanently erase an outbound message that remains in a sender's local outbox. Permanent globally authoritative handle registration remains a later protocol problem.

## Legacy mail work

The repository still contains the earlier JMAP/Stalwart and Resend experiments for reference. They are no longer the default product direction.

Quantic Network does not require SMTP, MX, IMAP, SPF, DKIM, DMARC, a purchased domain, or a Gmail/Outlook account for communication between Quantic identities.
