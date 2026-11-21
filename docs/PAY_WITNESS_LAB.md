# Four-machine fictional Pay laboratory

Status: preparation, not deployed. Each Linux machine requires Node 24 with ML-DSA-65 and node:sqlite. Use an isolated test network and a dedicated operating-system account. No bank data or real funds.

Each witness has a separately generated Ed25519 private key, independently pinned SHA-256 of its public SPKI, its own private directory and SQLite database, and a separate random 32-byte hex laboratory token. Never copy another witness's key or database. Provision the wallet's synthetic signing and PQ pins out of band.

The local operator creates a private JSON file (0600) in a trusted directory with these fields:
- simulationOnly: true
- directory: absolute, nonexistent private store directory on provision
- scope: signingPin and pqPin (64 lowercase hex each, fictional Pay keys)
- authorityKeyFile: absolute private PEM file, 0600, Ed25519
- authorityPin: independently obtained SHA-256 SPKI pin
- token: independently generated 64 lowercase hex characters
- port: fixed local HTTP port

Run once: node scripts/serve-pay-witness-lab.mjs provision /absolute/private/config.json
Then: node scripts/serve-pay-witness-lab.mjs serve /absolute/private/config.json

The service binds only 127.0.0.1. Do not publish it through a reverse proxy. To cross machines, separately provision one authenticated Pay-only Scattering link per witness, using the pay-lab profile, a unique secret and epoch, and the witness's local service as relay upstream. The wallet-side aggregator accepts four distinct loopback ports and tokens and requires three responses, then the existing signed checkpoint verifier independently checks 3/4 pinned keys. Carrier process orchestration on four remote machines and native Windows wallet integration are not yet complete.

Test: confirm one fictional operation, restart witnesses, verify exact history, stop one witness and confirm another operation, stop a second and refuse. Restore an old wallet proof set and verify mismatch. Do not retry a partially acknowledged submission or recreate a missing database. No recovery protocol, independent operator audit, Byzantine consensus or synchronized rollback defense is provided. Witness signatures remain Ed25519, not post-quantum. The test uses separate processes on the same Linux host, direct loopback HTTP, not four physical machines.
