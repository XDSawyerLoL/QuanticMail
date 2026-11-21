# QuanticMail Windows PQ — unsigned portable laboratory
Synthetic identities only. No production release or installer. Requires local fixed NTFS, a trusted installation directory, an attached Windows console and separately installed Node.js 24.8.0 or compatible Node 24 with ML-KEM and ML-DSA support. No passwords or account configuration included. SHA256SUMS is a build inventory, not an independently authenticated publisher signature.

Native executable: bin/Vault-PQ-lab.exe. The existing --provision-windows-pq-storage-lab command creates a new local encrypted identity, requires two passphrases, and refuses an existing directory. Before use, independently provisioned, ACL-validated desktop.json, controller.pem, quorum.json, contacts.json, peer TLS key/certificate files and valid classical/PQ authority grants must exist. No automatic enrollment or migration is provided. Do not copy real credentials into this test build.

Node command: node scripts/native-vault-windows-local.mjs ABSOLUTE_EXE_PATH TRUSTED_SHA256 PRIVATE_DIRECTORY open ABSOLUTE_WIRE_FILE. Other operations: recover-open, seal, recover-seal (last two require new wire output path). Independently establish the binary pin and installation integrity. A sealed result is saved locally, never automatically sent. No mailbox acknowledgements. Existing Electron 38 is not a supported runtime for PQ; the future Node 24 desktop UI is not packaged here.

No power-loss, WAN or physical-machine validation is implied. Do not install as a production identity provider.
