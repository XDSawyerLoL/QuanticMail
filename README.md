# QuanticMail

QuanticMail is the local-first messaging product of Quantic Sillage.

QuanticMail is not designed around Gmail-style hosted mailboxes or SMTP as its core transport. The product uses its own Quantic Network identities such as `sansa@quantic`, with a self-certifying canonical identity such as `sansa~4f82a19c2d@quantic`.

## V0.9 architecture

- **Human identity:** `name@quantic`
- **Canonical identity:** `name~fingerprint@quantic`, derived from the master identity signing key
- **Root device:** retains the master identity signing private key
- **Linked devices:** each has its own ECDH P-256 encryption key, device signing key and auth token
- **Device authorization:** a root-signed Quantic device certificate
- **Message encryption:** AES-256-GCM with per-device ECDH P-256 key agreement
- **Multi-device delivery:** one independently encrypted envelope per authorized recipient device
- **Per-device mailbox:** relay queues and delivery receipts are scoped to a device ID
- **Local mailbox:** browser IndexedDB
- **Durable local outbox:** encrypted device deliveries remain local until acknowledged
- **Identity recovery:** password-encrypted `.quantic-vault` for the root identity
- **Directory and temporary relay:** Render

The master identity signing private key does not need to be copied to linked devices. A linked phone or PC receives only its own private device keys plus a certificate signed by the root identity.

## Current deployment

- **Web application:** `https://quanticmail.onrender.com`
- **Device manager:** `https://quanticmail.onrender.com/devices`
- **Identity Vault:** `https://quanticmail.onrender.com/vault`
- **Network:** Quantic Network V0.9 alpha

## V0.9 capabilities

- create a human-readable `@quantic` identity
- derive a self-certifying canonical identity
- prove root ownership with ECDSA P-256
- create a new device request without exposing private keys
- sign a device certificate on the root device
- install the certificate on a secondary device
- re-register a linked device after a relay restart using the certificate
- resolve all authorized recipient devices
- encrypt a separate message copy for every recipient device
- keep each device mailbox isolated on the relay
- return delivery receipts to the exact sender device
- keep readable messages local to each browser/device
- preserve V0.8 encrypted Identity Vault recovery for the root identity

See [`docs/V0.9-MULTI-DEVICE.md`](docs/V0.9-MULTI-DEVICE.md).

## Pairing flow

1. On the new device, open `/devices`, enter the canonical Quantic identity and a device label, then create a `.quantic-device-request` file.
2. Move that request file to the root device.
3. On the root device, open `/devices`, load the request and sign it. QuanticMail produces a `.quantic-device-cert` file.
4. Move the signed certificate back to the new device and install it.
5. The new device registers with the relay using its own auth token and certificate.

The request file contains public device keys only. The certificate contains public identity/device data plus the master signature. The root private signing key never appears in either file.

## Message fan-out

When sending to a V0.9 identity, QuanticMail resolves the authorized device list and encrypts the message independently for every device public key. A compromise of one device private key does not provide the private keys of the other devices.

Each encrypted delivery has its own outbox record and delivery receipt. The readable sent message is still stored only once in the sender's local mailbox.

## Zero-cost durability model

Render Free web services use ephemeral local storage. QuanticMail therefore does not treat the relay as the durable authority for identity ownership, device authorization or undelivered content.

- identity ownership is proven by the master signing key;
- linked-device authorization is proven by the root-signed device certificate;
- unsent/unacknowledged encrypted deliveries remain in the sender's local outbox;
- a linked device can re-register from its local certificate after a relay restart.

A Render restart can still clear temporary queues and device-directory state. Active devices rebuild that state by re-registering.

## Security boundary

The root device can authorize new devices because it holds the master identity signing private key. Linked devices intentionally cannot authorize additional devices. Revocation, QR pairing and synchronized message history are future protocol layers; V0.9 focuses on independent device authorization and live encrypted delivery.

## Legacy mail work

The repository still contains the earlier JMAP/Stalwart and Resend experiments for reference. They are no longer the default product direction.

Quantic Network does not require SMTP, MX, IMAP, SPF, DKIM, DMARC, a purchased domain, or a Gmail/Outlook account for communication between Quantic identities.
