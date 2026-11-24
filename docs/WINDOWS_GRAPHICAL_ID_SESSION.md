# Graphical Quantic ID session (private Alpha)

The dashboard now exposes "Quantic ID - Ouvrir ma session". Choose the
existing provisioned test vault, supply the independently authenticated
SHA256 of its session configuration, and approve the native possession
prompts. The session dialog shows only the authenticated address, a
limited-duration status and a lock/close button. It never receives a
session identifier, password or private key. The controller runs hidden
with redirected pipes. Closing the dialog closes the pipe, invalidates
local access and requests remote lock. A network failure is not a
confirmed remote lock; the remaining server lease is at most 60 seconds.

The operator must already have enrolled the synthetic candidate with at
least three independent laboratory authorities and provisioned the
relying-party service. The private vault must contain session.json, an
operator-approved JSON object with exactly:
- format: quantic-native-session-config-lab/v1
- labOnly: true
- service: pinned HTTPS relying-party URL and tlsPin
- authorities: four independently approved HTTPS authority descriptors
  with url, tlsPin, pin and publicKey
- candidate: the exact inactive owner-signed identity candidate
- expected: independently approved public identity pins
- enrollmentReceipts: three or four verified enrollment receipts
- clientPin: SHA256 of the pinned client certificate DER
- tlsFiles: object with ca, cert and key (basenames of protected peer-*.pem files)

The configuration is not itself a session or an access token. Import it
and any required PEM files into the vault via the existing exclusive
native laboratory import mechanism, with independently approved digests.
No replacement of existing files is allowed. Keep the TLS private key
inside the approved local Windows security boundary. The normal session
dialog does not require manual editing of any JSON; initial operator
preparation remains a separate laboratory requirement.

The bundled runtime reads the configuration through the native private
file helper, checks its independent digest, verifies the package manifest,
and uses the native graphical prover and WTS watcher. A lock aborts an
outstanding native credential proof. This is not yet a physical-machine
acceptance test, and it authorizes only the synthetic identity lookup,
not Quantic Mail production access or payment. No account migration or
public deployment is performed.
