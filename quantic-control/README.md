# Quantic Control — Alpha 1 + durable authorization lab (experimental)

This directory is an isolated, native Go prototype for Quantic Sillage machine security. It does NOT modify QuanticMail messaging, install a system service, connect to the network, run remote commands, intercept input, or disable operating-system protections.

## Implemented

- A local authorization guard with pinned Ed25519 public keys and domain-separated signed claims.
- Strict read-only operation allowlist: status.read, integrity.scan, alerts.read.
- Machine binding, short expiry (maximum 120 seconds), clock-skew bounds, per-key nonce replay check, and in-process revocation.
- Opt-in SHA-256 integrity baselines for up to 128 small regular files (32 MiB each), with missing/modified/inaccessible reporting.
- A developer CLI that can be built as a native Windows executable (no Node, web client or PowerShell runtime required).
- Automated Go tests and cross-platform build verification.

## Durable local authorization experiment

The new Go API provides `InitDurableGuard` (explicit enrollment) and `OpenDurableGuard` (restart with independently pinned public keys), with `Authorize` and `Revoke` operations.

- The append-only journal stores machine binding, enrolled public keys, used nonces, and revocations. Data is flushed with `fsync` **before** granting authorization, with an exclusive OS file lock for Windows and Unix. A process-crash test exits without cleanup and verifies a replay stays rejected after the next process starts.
- A missing, truncated, corrupted, concurrently opened, re-enrolled, or untrusted-key state fails closed. Stored nonces are not discarded on clock rollback.
- The journal has finite capacity (100,000 records / 64 MiB); reaching the limit stops authorizations until a separately audited rotation protocol exists.
- **Not tamper-proof:** the hash chain only detects unintentional corruption and simple modification. A local attacker with write access could recompute it or roll it back. Secure monotonic anchors, protected Windows ACLs and an independent operator key root remain blockers before real remote use.
- This API is currently library-only, without network, service, administrator privilege, or automatic device enrollment. It is not integrated into the developer CLI or the native UI.

## Local developer demo

From quantic-control:

    go test ./...
    go run ./cmd/quantic-control status
    go run ./cmd/quantic-control baseline ./go.mod > baseline.json
    go run ./cmd/quantic-control scan baseline.json

The baseline file itself is NOT authenticated; an attacker who can edit it can change expected hashes. Use test files only. The CLI is for developers, not the final graphical user experience.

## Important security boundaries

- No antivirus, EDR, kernel driver, remote controller, central console or Windows service is implemented.
- The guard is not connected to a network listener. No remote request can be issued or executed.
- The original in-memory `Guard` remains unchanged. The new opt-in `DurableGuard` persists revocations and replay state across clean restarts and abrupt process exit, but requires an independently pinned enrollment key list. There is no safe general-purpose enrollment ceremony or anti-rollback anchoring yet, so remote operations remain disabled.
- Identity Vault / ML-KEM / ML-DSA integration is planned, not claimed. Ed25519 here is a conventional signature primitive used to test the authorization boundary.
- Local file baselines are unsigned, so integrity findings are diagnostic and not tamper-proof. No remediation occurs.
- Alpha 1 is not for production deployment. Do not merge or package as a security product without a threat model, durability tests, signed builds, privilege review and an external audit.

## Next gates

1. Complete durable state security: authenticated anti-rollback anchoring, protected Windows ACL, independent key enrollment/recovery and power-loss testing (the initial fsynced journal and process-crash replay tests now exist).
2. Integrate real Quantic ID / Identity Vault, without exposing private keys or reusing message signing domains.
3. Add a minimal, non-privileged Windows background agent and genuine native GUI with explicit consent and uninstall support.
4. Add signed, recoverable security policies, attack simulations and independent Windows runner tests before remote control.
