# Quantic Control — Alpha 1.2 authorization and signed state anchor lab (experimental)

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

## Independently signed rollback checkpoint (Alpha 1.2)

The optional `AnchorProposal` and `AnchorSigningBytes` APIs export a public-only, domain-separated state proof. An **independent** Ed25519 authority can sign it and `OpenPinnedDurableGuard` validates the exact pinned journal contents and sequence after reopening.

- A fully valid earlier journal or a hash-chain rewritten by a local attacker is rejected if the caller provides the **latest authentic checkpoint from an independent trust channel**.
- There is **no** anti-rollback guarantee if an attacker can also replace that external checkpoint or its trusted public-key pin.
- Each journal append invalidates the previous checkpoint. This library does not automatically obtain a new external signature, so no always-on remotely controlled service is ready.
- This is a **future Identity Vault integration boundary**, not a current Quantic ID/ML-DSA implementation. See [STATE_ANCHOR_SECURITY.md](STATE_ANCHOR_SECURITY.md).

## Native Identity Vault checkpoint protocol bridge (Alpha 1.3)

The opt-in `VaultWitness` client speaks the **existing native Identity Vault** separate authority `/check` + `/advance` protocol from PR #48. It requires independent TLS 1.3 mTLS credentials, an exact server certificate pin and a separately provisioned witness identifier. The client binds the existing signed Control state anchor to Vault's monotonically advancing checkpoint and can detect rollback of **both the journal and a locally cached signed anchor**, as long as the remote witness is trusted and reachable.

These are **laboratory, not production**, APIs. The code neither creates an external witness nor integrates Identity Vault's native signing keys; tests use a local TLS simulation of the protocol. There is no transactional recovery from uncertain remote advances and no network authorization gate.

See [VAULT_WITNESS_BRIDGE.md](VAULT_WITNESS_BRIDGE.md) for the exact JSON, security boundaries and remaining failures.

## Native Windows graphical Alpha (local file diagnostic)

A separate Win32 GUI app (`cmd/quantic-control-gui`) now lets a user choose a file, remember its SHA-256 fingerprint in memory and verify whether it changed, using the Windows file chooser. It has **no visible console or JSON configuration** and does not contact any server. Its output is diagnostic only: it is *not* malware detection or a background protection service. The signed remote witness and Identity Vault guard are **not** wired to this GUI yet.

Build with `go build -ldflags="-H windowsgui" -o quantic-control-gui-alpha.exe ./cmd/quantic-control-gui` on Windows. The unsigned binary is built and uploaded by GitHub Actions for laboratory evaluation; not an installer. Read [WINDOWS_GUI_ALPHA.md](WINDOWS_GUI_ALPHA.md).

## Quantic Sentinel — monitored Windows folders (next lab milestone)

The new **separate** `cmd/quantic-control-sentinel` Win32 binary periodically scans (every 2 seconds) metadata of up to 5,000 directory entries in a user-selected folder and its subfolders. It **automatically reports** bursts of file modifications, deletions and suspicious renames, with no console, browser, remote requests or privileged system modifications. Its local session dashboard shows recent anomalies and can stop monitoring without a background service. It does not replace Defender or prevent malware. This is the first automatic **observation** capability, not an endpoint-protection product.

Build on Windows with `go build -ldflags="-H windowsgui" -o quantic-sentinel-alpha.exe ./cmd/quantic-control-sentinel`. Windows/Linux CI tests changed-file detection, cancellation and binary subsystem. The unsafe asynchronous Windows notification prototype was removed after a Windows runner crash. See [SENTINEL_ALPHA.md](SENTINEL_ALPHA.md) for exact detection thresholds, constraints and remaining gates.

## Quantic Sentinel Windows resident mode (Alpha)

The **same** Win32 GUI program now optionally installs a **per-user**, unelevated background agent when the user clicks **Installer pour ma session Windows**. It copies the verified executable into LocalAppData, registers only an **HKCU Run** entry, and starts monitoring the explicitly selected folder. Monitoring continues after the GUI closes and starts again at the next user sign-in. Local, bounded JSONL audit records are readable from the GUI via **Historique local**. **Désinstaller** removes only registered startup and known installation files, leaving logs intact.

**It is not a Windows SCM service** and does not operate before logon or after sign-out. The agent cannot block ransomware or reliably identify malicious processes. No production Identity Vault integration. Read [SENTINEL_RESIDENT_ALPHA.md](SENTINEL_RESIDENT_ALPHA.md) for exact behavior, cleanup rules and remaining validation requirements.

## Microsoft Defender CFA event evidence (Alpha 1.5)

The opt-in **resident** Windows user agent now reads the **native local Defender Operational Event Log**, without invoking PowerShell or changing Defender policy. It looks only at official Controlled Folder Access event IDs 1123/1124/1127/1128, distinguishes **blocked** from **audited**, and keeps process names/PIDs only when **explicitly supplied by the Defender EventData**.

Its local history includes the relevant Defender evidence and conservative manual next steps. Sentinel's own folder scanner cannot attribute file changes to processes: nearby timestamps and folders are **context only**, not a causal link. Defender log unavailability and poll overflow are visible, not silently masked. There is **no** auto-terminate, quarantine, process suspension or isolation.

See [SENTINEL_DEFENDER_CFA.md](SENTINEL_DEFENDER_CFA.md) for technical limits, native Windows API and validation gates.

## Process-file audit evidence and verified Windows installer test

A new read-only native Windows Security Event Log **4663** reader records the process and PID that Windows explicitly associates with the use of write-capable access rights on a file within the watched folder. This does **not** attribute every file modification, prove malware, or authorize process termination; a SACL and Windows audit policy must already permit the source event. The agent degrades visibly when access is denied.

Windows CI now tests the **actual compiled Win32 GUI binary** as a background process, verifies an alert after 25 harmless file changes, and performs reversible HKCU startup removal and targeted uninstall. The test does not establish autostart after a real Windows logout/login cycle.

An optional **publisher Authenticode signing workflow** can sign and Windows-verify this executable only once real publisher certificate secrets are configured. The Alpha is **unsigned** and is not ready for release. Quantic ID/Identity Vault do not yet authorize this resident agent, and Sentinel itself cannot prevent ransomware. See [SENTINEL_RELEASE_GATES_2026.md](SENTINEL_RELEASE_GATES_2026.md) for precise evidence and outstanding gates.

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

1. Complete durable state security: externally protected *latest* signed anchor, protected Windows ACL, independent key enrollment/recovery, secure checkpoint rotation and power-loss testing (fsynced journal, process-crash tests, and optional external anchor verification now exist).
2. Integrate real Quantic ID / Identity Vault, without exposing private keys or reusing message signing domains.
3. Add a minimal, non-privileged Windows background agent and genuine native GUI with explicit consent and uninstall support.
4. Add signed, recoverable security policies, attack simulations and independent Windows runner tests before remote control.
