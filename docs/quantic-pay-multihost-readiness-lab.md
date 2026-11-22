# Quantic Pay — real multi-host witness readiness (experimental only)

This checklist is for testing the witness service on independently
administered **Linux machines**. No machines are provisioned or remotely
accessed by this repository. The CI test uses separate Node processes on
one GitHub Actions runner and must never be marketed as physical redundancy.

## Topology and prerequisites

The experimental 3/4 anti-rollback quorum needs four witness hosts for
**each** shard (eight hosts for a two-shard test). A witness runs
`scripts/quantic-pay-witness-node-lab.mjs` under its own non-admin Linux
account and stores **one separate SQLite fence** and two private signing
keys (Ed25519 + ML-DSA-65). Use a current Node version exposing
`ml-dsa-65` and `node:sqlite` (the CI uses Node 24.8.0), plus a
mutually authenticated TLS 1.3 endpoint.

The host operating system, storage, network and certificate authority
must be administered separately for the assumptions of the design to hold.
Different TCP ports on the same machine, multiple VMs on the same storage
pool, or different DNS names alone are **not** proof of independence.

The witness SQLite backend currently **requires Linux**. Windows is not a
supported witness host, regardless of the availability of other Quantic
native Windows components.

## Per-host key setup

1. Create a private witness account and a private storage/configuration
   directory owned by it, mode `0700`; do not use a shared account.
2. Generate the Ed25519 and ML-DSA-65 private signing keys independently
   on that host. Pin their SPKI SHA-256 public identities in the same
   immutable public witness roster distributed to all four peers.
3. Install a **unique** TLS server key/certificate with a correct DNS/IP SAN,
   signed by an operator-controlled CA. Configure an explicit SHA-256
   fingerprint of the DER server certificate on the controller.
4. On the server, permit only the controller's pinned TLS client certificate
   fingerprint. Limit the TCP port to the trusted controller's addresses
   through host firewall rules. Do not open the RPC to the public Internet.
5. Put private key PEM files, TLS certificate, CA bundle and config JSON in
   private mode `0600`. The private loader checks owner, private parent,
   regular file, no symlink/hardlink, inode consistency and size bounds.
6. Use `createNew:true` only for a **deliberately new** witness store; use
   `createNew:false` thereafter. Do not create a new journal after a
   crash. Preserve the existing independently controlled SQLite history.
7. Do not place signing keys, API tokens or certificate private keys in CLI
   arguments, logs, a Git repository or the controller's JSON configuration.

A private key remains usable in the Node process address space. The current
loader is **not** a TPM/HSM or a shield against root compromise or process
memory extraction. Do not use production money with this implementation.

## Operator preflight

On the trusted controller, prepare a private file
`/private/controller/preflight.json` under a mode `0700` directory.
It must contain the public ledger configuration and roster, the
**independently verified** final source checkpoint and anchor, and the four
pinned TLS endpoints:

```json
{
  "config": {"shards": [], "wallets": []},
  "options": {
    "reservationsEnabled": true,
    "crossShardAtomicEnabled": true,
    "inboundPreparationEnabled": true
  },
  "shard": "demo-east",
  "witnesses": [],
  "peers": [
    {"url": "https://w1.example.test:9443/v1/witness", "serverCertPin": "<64-hex>"},
    {"url": "https://w2.example.test:9443/v1/witness", "serverCertPin": "<64-hex>"},
    {"url": "https://w3.example.test:9443/v1/witness", "serverCertPin": "<64-hex>"},
    {"url": "https://w4.example.test:9443/v1/witness", "serverCertPin": "<64-hex>"}
  ],
  "tls": {
    "keyPath": "/private/controller/client.key",
    "certPath": "/private/controller/client.crt",
    "caPath": "/private/controller/servers-ca.crt"
  },
  "checkpoint": null,
  "anchor": {"network": "<64-hex>", "shard": "demo-east", "height": 0, "root": "<64-hex>"},
  "allowSingleHostLab": false
}
```

**Placeholders are nonfunctional.** Replace the empty public rosters and
synthetic hashes with the actual trusted configuration and use a certified
checkpoint whenever `anchor.height > 0`. At genesis `height:0`, the
checkpoint must be null and the root must match the locally computed genesis.

```bash
chmod 700 /private/controller
chmod 600 /private/controller/preflight.json /private/controller/client.key
export QUANTIC_PAY_MULTHOST_PREFLIGHT_CONFIG=/private/controller/preflight.json
node scripts/quantic-pay-multihost-preflight-lab.mjs
```

The tool checks all four endpoint strings and **distinct server certificate
pins**, mutually authenticates TLS and requires at least three distinct,
fresh Ed25519 + ML-DSA-65 signatures on the same independently certified
checkpoint. With `allowSingleHostLab:false`, it also refuses obvious
loopback addresses and identical hostnames. It never confirms physical
independence; this still requires an operator inspection of actual machines,
administration accounts, hardware, storage and routing.

The `allowSingleHostLab:true` flag exists **only for CI tests**. It allows
four different ports on loopback but all outputs remain marked
`physicalIndependenceVerified:false` and `realPaymentAuthorized:false`.

## Failure drills before any larger trial

- Stop one witness: quorum of the other three should still attest.
- Stop two: all authorization requiring 3/4 must refuse; no timeout may
  be interpreted as an ABORT, COMMIT or permission to overwrite a journal.
- After a prolonged partition, restore a third: verify a single resumed
  credit and bounded exponential reconnection retries, without duplicate
  receipts.
- Restart a lagging witness: it may catch up only from its own certified
  prefix, a fresh internal challenge and three peer signatures.
- Reintroduce an old disk snapshot, reused TLS certificate, changed
  public roster, mismatched SPKI key, cloned certificate or revoked client:
  the operation must refuse until corrected through a reviewed migration.
- Measure CPU, memory, disk durability, latency, TLS timeout distribution,
  rate-limit exposure and clock drift on **physically separate** machines.

The current protocol does not provide key rollover, live revocation
distribution, real financial licensing, regulatory approval, proven
Byzantine availability under all partitions, a dedicated hardware
key boundary or euro numérique integration. No commercial deployment
or financial transaction is authorized by these tests.
