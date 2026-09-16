# QuanticMail

QuanticMail is the local-first messaging product of Quantic Sillage.

Starting with V0.5, QuanticMail is no longer designed around Gmail-style hosted mailboxes or SMTP as its core transport. The product now uses its own Quantic Network identities such as `vnhz@quantic`.

## V0.5 architecture

- **Identity:** human-readable `name@quantic`
- **Client:** Next.js / React / TypeScript
- **Device crypto:** Web Crypto, ECDH P-256 + AES-256-GCM
- **Local mailbox:** browser IndexedDB
- **Directory and relay:** Render
- **Readable message storage:** user device
- **Relay storage:** encrypted envelopes only

The private identity key stays on the user's device. Render receives routing metadata and ciphertext, not plaintext message content.

## Current deployment

- **Web application:** `https://quanticmail.onrender.com`
- **Network:** Quantic Network V0.5 alpha

## V0.5 alpha capabilities

- create and reserve a `@quantic` identity
- generate identity encryption keys locally
- resolve another Quantic identity
- encrypt messages in the browser before sending
- temporarily queue encrypted envelopes on Render
- receive and decrypt messages on the recipient device
- acknowledge only after local persistence succeeds
- store readable sent and received messages in IndexedDB
- automatic polling plus manual synchronization

See [`docs/V0.5-QUANTIC-NETWORK.md`](docs/V0.5-QUANTIC-NETWORK.md).

## Important alpha limitation

The current Quantic directory and encrypted relay queue are process-local. A Render restart or redeploy can clear reservations and pending encrypted envelopes. Messages already downloaded and saved locally remain on the user's device. Durable zero-cost persistence is the next infrastructure target.

## Legacy mail work

The repository still contains the earlier JMAP/Stalwart and Resend experiments for reference. They are no longer the default product direction.

Quantic Network does not require SMTP, MX, IMAP, SPF, DKIM, DMARC, a purchased domain, or a Gmail/Outlook account for communication between Quantic identities.
