# Graphical Quantic ID session (private Alpha)

## Operator preparation

The test candidate and its device pins must be independently approved by
the operators of the four authority services and the relying party. A kit may
contain an explicitly empty enrollmentReceipts array for first enrollment.
For this mode the relying party must start with allowInitialEnrollment:true
and enrollmentReceipts:[]. It verifies three signed enrollment receipts
before issuing its own login challenge. No trust is derived from the client. This remains a
private laboratory workflow, not self-service enrollment or production access.

In a private Linux directory (mode 0700) place configuration.json and the
three corresponding peer-*.pem files (mode 0600). The configuration schema
is exactly:
- format: quantic-native-session-config-lab/v1
- labOnly: true
- service: pinned HTTPS relying-party URL and tlsPin
- authorities: four approved HTTPS descriptors (url, tlsPin, pin, publicKey)
- candidate: exact inactive owner-signed identity candidate
- expected: independently approved public identity pins
- enrollmentReceipts: explicitly empty for initial enrollment, or three or four signed receipts
- clientPin: SHA256 of the pinned client certificate DER
- tlsFiles: distinct basenames ca, cert and key

Run with Node 24:

    node --experimental-transform-types scripts/prepare-native-session-kit.mjs /absolute/private/directory

The builder validates the identity manifest, PQ profile, device pins,
enrollment receipts, distinct authority and TLS pins, certificate/key match
and file names, then exclusively creates session-kit.json and reports its
SHA256. No device private key is included. The kit DOES contain the mTLS
client private key and is NOT encrypted by the builder. Transfer it only
through a separately protected confidential channel; communicate the digest
via an independently authenticated channel. Do not email the raw kit or
place it in a shared/public folder.

## Windows user

Choose "Quantic ID - Activer ma configuration" in the graphical dashboard,
select the existing test vault and the protected session-kit.json, enter
the independently received kit digest once, and confirm. The native
importer binds the kit to the exact vault identity and TLS keypair, refuses
any conflicting existing file and creates the local approval marker last,
after rereading all files. Identical interrupted imports may resume.
The marker is protected by the existing NTFS security boundary; it is not
a defense against the same trusted Windows account being compromised.

Choose "Quantic ID - Ouvrir ma session". With an initial enrollment kit,
the controller obtains independent durable enrollment receipts using the
native four-key possession proof, then performs fresh authentication.
On later launches it retrieves the existing signed receipts from the
authorities; no locally persisted session or new enrollment is required
where receipts already exist. Closing or locking the client interrupts
subsequent proof operations, but cannot undo a previously committed
approved enrollment. No repeated configuration digest
or manual JSON editing is needed. The controller independently verifies the
approved file hashes, signed receipts and TLS pair before network access.
The window shows only the authenticated test address, status and lock button.
Closing the pipe locks the client and requests remote lock; a failed
remote lock remains subject to the server's 60-second lease.

Existing manually configured laboratory vaults need the approved kit
import before using the new dashboard. The old direct controller interface
still accepts an independently authenticated configuration digest.
No legacy migration, production account activation, real mail permission,
physical-host acceptance or signature of the installer is implied.
