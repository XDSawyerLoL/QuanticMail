# Quantic Control — independent signed anchor experiment (Alpha 1.2)

## What is implemented

The local Go library can export a public-only, deterministic `AnchorPayload` for the current fsynced authorization journal:

- protocol version and fixed signing domain `QUANTIC-CONTROL/state-anchor/v1`;
- machine identifier, monotonic journal sequence and hash-chain head;
- SHA-256 of the **entire** journal on disk, including the JSON record framing;
- the separately pinned authority identifier.

An **independent** signer (future native Identity Vault authority) can sign `AnchorSigningBytes(payload)` with a signing key **not used as an enrolled operator key**. `OpenPinnedDurableGuard` verifies the public signature against a separately trusted public key and checks the *exact* journal state after normal journal integrity checks. Any mismatch closes the guard without allowing authorization.

The journal module never generates, stores, or accesses the authority's private key, and it has no network listener. The Ed25519 signature is a test integration boundary, **not** implemented ML-DSA-65 or Quantic ID integration.

## Mandatory independent trust boundary

The signer must be off-host or inside a separately audited, strongly protected environment. The **latest known signed anchor and signer public-key pin must be obtained from a source the local attacker cannot rewind**. Keeping the journal, anchor and trust root together in one writable folder defeats rollback detection if the attacker replaces all of them.

Exact-state verification is intentional. Every successful authorization or revocation appends to the journal; therefore a **new external signature is required before the next pinned restart**. There is no background signing, network witness or automatic checkpoint provisioning today. This is a laboratory protocol, not a usable always-on authorization service.

## Tested cases

- A valid independent signature allows a clean restart.
- Restoring a previously valid, correctly hashed journal is accepted by the *unanchored* guard but **rejected** by the independent pinned anchor.
- Rewriting a journal entry and recomputing its entire hash chain remains structurally valid but is rejected by the signed anchor.
- Wrong machine, forged signature, unknown authority ID or key, stale anchor and reusing the operator key as signing authority all fail.

Run `go test ./...` and `go test -race ./...` inside `quantic-control/`. Windows and Linux GitHub CI additionally test compilation and Windows executable startup.

## Not proven

- There is no guarantee against an attacker who can replace **both** the local state and the caller's trusted latest external anchor / root.
- There is no protection against kernel compromise, privileged local modifications while a process is running, compromised signers, power-loss semantics on every filesystem, or replay during a disconnected authority handoff.
- Windows DACL/reparse-point hardening, install/uninstall, security event telemetry, device enrollment, ML-KEM/ML-DSA, remote access and graphical UI are **not implemented** here.
- An unsigned local SHA-256 baseline remains diagnostic only; signing the state anchor does not authenticate independently selected baseline files.

## Next implementation gate

1. Native Identity Vault or separately managed authority signs these exact bytes under an audited key-custody and revocation policy.
2. Independently persist the **latest** anchor in anti-rollback storage or an authenticated external witness; define secure recovery and lost-witness behavior.
3. Audit the Windows state directory DACL, path traversal, reparse/symlink handling and tampering under multiple user accounts.
4. Test abrupt power loss, journal capacity and checkpoint rotation, then add a user-facing native GUI.
5. Only after passing those gates consider narrowly scoped remote-control operations.
