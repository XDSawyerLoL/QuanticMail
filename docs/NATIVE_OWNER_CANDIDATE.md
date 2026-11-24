# Native Quantic ID: owner-signed candidate (private laboratory)

This closes a format gap between a newly created Windows device vault and
the existing signed identity/crypto-profile authority protocol. It does
not publish an account, activate authority policy, or migrate an existing
identity. Device proof of possession and durable enrollment remain gates.

The owner must hold a P-256 ownership signing key and a distinct ML-DSA-65
ownership key on an independently protected owner workstation. Never send
those private keys to the relay or the authority. These keys are NOT the
device signing keys. The synthetic canonical address must be derived from
the owner signing key BEFORE the Windows device vault is created. Existing
arbitrarily named laboratory vaults cannot be silently reassigned.

On a trusted offline Linux workstation with Node 24, use a new private
directory (0700), with independently protected root keys and files (0600).
For a public-only address preview, provide owner-signing-public.pem and run:

    node --experimental-transform-types scripts/prepare-native-owner-candidate.mjs address /absolute/private/owner alice

Create the Windows test identity with that exact address and the separately
approved replay quorum pin. Transfer only its identity-public.json over an
authenticated channel. Independently approve the exact fields address,
deviceId, rootPin, pqRootPin, quorumPin, signingPin, encryptionPin, kemPin,
dsaPin and controllerPublic into approved-device-pins.json. Obtain its SHA256
from a separately authenticated approval channel. Place it and the public
device record in the owner's directory; the offline owner key files must
already exist as owner-signing.pem and owner-pq.pem. The command does not
generate, replace or export those ownership keys.

    node --experimental-transform-types scripts/prepare-native-owner-candidate.mjs prepare /absolute/private/owner alice APPROVED_PINS_SHA256

The command exclusively creates identity-candidate.json and independently
checks the generated signatures against the existing manifest/profile
verifiers and contact-binding code. The resulting policy is inactive,
devicePossessionVerified=false and registrationAuthorized=false. It must
NOT be manually switched active in a real environment. The CI test checks
synthetic compatibility with three independently keyed attestation votes;
it does not demonstrate a deployed authority network.

Remaining gates: a fresh challenge proving possession of the device keys,
owner-approved registration, durable compare-and-set publication and quorum
readback, plus actual remote transport. No legacy deletion.
