# Quantic Network implementation sequence

1. `2026-09-17-quantic-federation-v1.md` — direct signed relay federation and receipts.
2. `2026-09-17-quantic-crypto-v2-pqc.md` — hybrid P-256 + ML-KEM-768 + ML-DSA-65 and anti-downgrade.
3. `2026-09-17-quantic-discovery-mesh.md` — distributed signed discovery mesh without mandatory central registry.

The order is intentional: Federation V1 establishes portable sender proofs and relay-to-relay transport; Crypto V2 upgrades those proofs and envelopes; Discovery Mesh automates finding the signed identity/crypto/route bundle and destination relay.
