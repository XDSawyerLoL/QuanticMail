# Quantic Control — Alpha 1 (experimental)

This directory is an isolated, native Go prototype for Quantic Sillage machine security. It does NOT modify QuanticMail messaging, install a system service, connect to the network, run remote commands, intercept input, or disable operating-system protections.

## Implemented

- A local authorization guard with pinned Ed25519 public keys and domain-separated signed claims.
- Strict read-only operation allowlist: status.read, integrity.scan, alerts.read.
- Machine binding, short expiry (maximum 120 seconds), clock-skew bounds, per-key nonce replay check, and in-process revocation.
- Opt-in SHA-256 integrity baselines for up to 128 small regular files (32 MiB each), with missing/modified/inaccessible reporting.
- A developer CLI that can be built as a native Windows executable (no Node, web client or PowerShell runtime required).
- Automated Go tests and cross-platform build verification.

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
- Nonce replay state and key revocations are in memory only; they do not survive a process restart. Persistent state and a non-replayable enrollment ceremony must be implemented and tested BEFORE enabling any remotely initiated operation.
- Identity Vault / ML-KEM / ML-DSA integration is planned, not claimed. Ed25519 here is a conventional signature primitive used to test the authorization boundary.
- Local file baselines are unsigned, so integrity findings are diagnostic and not tamper-proof. No remediation occurs.
- Alpha 1 is not for production deployment. Do not merge or package as a security product without a threat model, durability tests, signed builds, privilege review and an external audit.

## Next gates

1. Persist pinned device identity, revocations and replay state with transactional crash/restart tests.
2. Integrate real Quantic ID / Identity Vault, without exposing private keys or reusing message signing domains.
3. Add a minimal, non-privileged Windows background agent and genuine native GUI with explicit consent and uninstall support.
4. Add signed, recoverable security policies, attack simulations and independent Windows runner tests before remote control.
