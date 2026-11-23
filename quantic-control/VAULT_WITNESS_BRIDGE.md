# Quantic Control — Native Identity Vault independent witness protocol bridge

This is a **protocol adapter** for the existing **Quantic native Vault** independent checkpoint service on branch `feat/identity-vault-security-hardening-20261121` (PR #48), whose source lives at `labs/quantic-native/vault/anchor_server.py` and `anchor.go`. It is **not** a production Identity Vault integration or an automatic anti-rollback service.

## Exact wire compatibility with Vault service

The Vault service is separately provisioned by its local operator with one 64-character lowercase hexadecimal `id`. Its initial checkpoint is `(id, count=0, tail=id)`. The explicit, pre-provisioned identity and the newest valid checkpoint must be held outside the machine's rollback domain.

The Control adapter accepts a caller-supplied, trusted TLS configuration: HTTPS endpoint without credentials or paths, a trusted CA, a SHA-256 **exact server leaf certificate pin**, and a mutual-TLS client certificate/private key. TLS 1.3 minimum, no redirects, short timeouts, and exact expected `OK\n` responses are required.

- `POST /check`: JSON keys `id`, `count`, `tail`, all matching the witness' independent durable state, returns `OK\n` on success.
- `POST /advance`: additionally `record` (64-character SHA-256 hex), requires an exact current cursor. The existing Vault server advances `tail = SHA256(hex_decode(old_tail) || hex_decode(record))`, `count += 1`.
- `WitnessRecordDigest(SignedAnchor)` hashes an independently signed Control state anchor with explicit domain separation, without sending the journal itself or private keys.
- `CheckPinnedVaultWitness` verifies the Control anchor's signature and current local journal, **then** verifies the cursor against the independent Vault service. `AdvancePinnedVaultWitness` binds a signed snapshot to the witness using its existing monotonic protocol.

The Go module does **not** provision, administer, reset, or recover an external Vault witness. It does **not** use a messaging relay, a browser, a VPS, or public keys read only from a possibly rolled-back journal.

## Laboratory scenario covered by tests

1. Initialize a local Control guard with explicit operator public keys and an independent authority key; provision an isolated witness ID.
2. Generate a signed anchor and advance the witness to a first checkpoint.
3. Append an authorization to the fsynced journal, sign the new state, advance the witness again.
4. Roll back **both** the journal and the locally cached signed anchor/cursor.
5. Local signature and journal checks alone accept that self-consistent old state; the independent witness's `/check` returns an error and the Control API refuses the checkpoint.
6. Simulate missing witness or mismatched counter and ensure refusal.

Tests currently use a **local TLS 1.3 witness simulation** matching the pre-existing service's `/check` and `/advance` JSON and hash semantics, including client-certificate presentation. They do **not** operate a real deployed Vault authority. Windows and Linux CI validate the compiled Go integration.

## Critical unsolved conditions

- Vault's real independent server must be set up on a distinct trusted host, with true server-side client certificate verification, operator provisioning, and external custody. A simulated witness on the same host is **not** independent.
- An authenticated, authoritative signer holding the *latest* anchor signing key outside the controlled host is still missing. Ed25519 here is a test key, not Identity Vault's native PQ signature path.
- A caller must already know the correct **current** cursor and authority key. If an attacker replaces both local journal and cursor, remote `/check` detects rollback only if the independent witness remains intact and reachable.
- A witness `/advance` can commit even when the client's reply is lost: **do not automatically retry** an ambiguous mutation. Operator-guided reconciliation is not implemented.
- No atomic coupling between authorization journal append, signed-anchor issuance, and remote witness advance. `CheckPinnedVaultWitness` is only a snapshot check; it **must not be used as a remote command authorization gate** until this protocol has a safe transactional/recovery design.
- The existing Vault service's 16,384 checkpoint limit and disk/full-power-loss edge cases need policy, rotation and independent recovery.
- No network listener, remote shell, surveillance daemon, Windows DACL management, policy enforcement, native GUI, installer or production protection is added.

### Gate for next release

Implement an independently protected and recoverable signer/witness enrollment flow, securely bind the operator and machine identity to Quantic ID, and test the exact production Vault server with independent certificates/keys. Only then can witnessed authorization be considered for a real agent.
