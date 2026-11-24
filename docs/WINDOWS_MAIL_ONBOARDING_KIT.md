# Windows mail configuration kit (private Alpha)

The new graphical action "Quantic Mail - Activer ma configuration de test"
imports a configuration prepared by a trusted operator for a **specific**
local test identity. It does not create an account on the network, generate
authority credentials, or prove remote delivery.

The operator must already have provisioned the four checkpoint authorities,
their mTLS client material, the approved peer contact and a separate
Scattering carrier. Obtain the public identity record of the new local vault
through a trusted channel. The kit must use the exact target vault directory,
installed vault executable path and independently authenticated executable
SHA256. The checkpoint TLS-pin quorum must equal the quorum pin bound to the
vault at creation. Never change the local identity to match a kit.

The kit is an UTF-8 JSON object with exactly these fields:

- format: "quantic-windows-mail-kit-lab/v1"
- address: the local synthetic canonical address
- deviceId: the exact native device ID
- files: object mapping desktop.json, quorum.json, contacts.json and the
  referenced peer-*.pem files to canonical unpadded base64url file bytes.

All paths in the desktop and quorum configurations refer to the destination
vault, not the operator staging directory. Only these configuration files
are accepted. The controller key, receipt key, encrypted vaults, journal and
historical identity are never imported. The maximum kit size is 131072
bytes, with at most 19 files of at most 65536 bytes each.

The kit is **confidential**, not encrypted by base64url. Deliver it through
an authenticated confidential channel, into a separate private NTFS
directory accessible only within the approved local security boundary.
Name it onboarding.json. Supply its SHA256 through an independent
authenticated channel. Do not send the kit via public mail or publish it.
The native private-file reader refuses unsafe NTFS objects or ACLs.

Select the already-created test vault and the kit in the graphical
dashboard, enter the independently obtained digest, and explicitly
approve. The native preflight checks identity, installed binary binding,
vault layout, replay quorum, TLS client keys, four distinct attestation
authorities, and contact parsing before import. All existing files are
checked before writing; identical prior writes may be resumed, conflicting
bytes refuse the entire preflight. Writes use the native exclusive private
file helper and each file is independently reread. A partial import is
preserved on failure; do not manually overwrite files.

After import, run the existing MailPreflight and MailAttest checks with
independently approved public trust pins and the provisioned carrier.
A local import is NOT a verified live authority quorum, delivery, account
registration, migration, or permission to use real identities.

The existing unsigned Alpha release gate remains unchanged.
