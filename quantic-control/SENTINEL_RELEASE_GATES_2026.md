# Quantic Sentinel — release gates as of 24 November 2026

This is a **provenance-based engineering status**, not a claim of antivirus effectiveness.

## A. Process attribution — partial, tested

Windows Security `4663` audit records contain `ProcessName`, `ProcessId`, `ObjectName`, `ObjectType`, and `AccessMask`. Sentinel's new read-only native Event Log collector only treats records as a possible file write when they originate from the expected Windows Security-Auditing provider/channel, explicitly reference a **File**, and record a write-capable access bit.

A 4663 event is evidence that a file access right **was used by the recorded process**, not evidence of maliciousness, successful ransomware encryption, or attribution of every Sentinel filesystem delta. A historical PID is not safe to use for a termination request. If Windows audit policy, per-folder SACL, or Security log permissions are missing, the resident agent records **file_audit_unavailable**, never invents a process name. It does **not** enable audit policy or change SACLs silently.

Microsoft 4663 reference: https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4663

## B. Automatic blocking — NOT implemented by Sentinel

Only Microsoft's existing **Controlled Folder Access** can currently prevent unauthorized writes in the target configuration. Sentinel can display Defender CFA events (1123, 1124, 1127, 1128) and open the Windows Security controls for an explicit user decision. There is **no** new Sentinel process-blocking engine, signed kernel file-system minifilter, prevention policy proven under attack, or safe automatic process suspension.

We must not ship an auto-kill feature based solely on the previous 30 seconds of filesystem activity or on a historical PID. False positives could interrupt legitimate programs, and a driver or service able to deny writes must undergo independent compatibility/security review.

Microsoft Defender CFA: https://learn.microsoft.com/en-us/defender-endpoint/controlled-folder-access-configure

## C. Quantic ID / Identity Vault — NOT operationally linked

The native Identity Vault branch and the Sentinel authorization prototype are **separate**. Quantic Control already has an experimental mTLS Vault witness adapter (PR #70) and independent signed journal anchors (PR #69), but Sentinel's resident process does not consume a production Vault identity, verify a current Vault-issued policy, or perform a real Quantic ID enrollment. The native Vault Windows ML-DSA storage/broker remains a laboratory feature on a separate PR.

Do not accept a public key or trust root solely from a file that an attacker can rewind alongside the journal; the authorization root and latest witness state must be independently pinned and recoverable.

## D. Windows installation and Authenticode

**Tested on actual Windows Actions runner** (`TestActualResidentBinaryInstallationE2E`): the newly built Win32 GUI executable is copied into a temporary LocalAppData, started with `--resident`, observes a burst of 25 harmless files, records the alert, and is shut down and uninstalled. Tests also verify the HKCU Run entry and preservation of an events log/unknown files.

Still missing: interactive GUI clicks on a physical Windows device, automatic launch at the next actual logon, upgrade/migration between versions, Apps & Features registration, independent security audit, supported installer packaging and a production recovery process.

**Authenticode pipeline prepared, but no trusted signature delivered.** The manual GitHub Actions workflow `.github/workflows/quantic-sentinel-signed-release.yml` requires these repository secrets:
- `QUANTIC_CODE_SIGNING_PFX_BASE64` — the real publisher's code-signing certificate with its private key, base64 encoded;
- `QUANTIC_CODE_SIGNING_PFX_PASSWORD` — its password;
- `QUANTIC_EXPECTED_PUBLISHER_SUBJECT` — the exact expected signer subject.

The signing script refuses mismatched publisher, missing private key, expired certificate and unsigned/Windows-untrusted result. It removes temporary signing material after use. This workflow is manual and may only be used after it is present on a branch where GitHub makes the workflow available. Do not commit certificate/private key or print secrets in logs. Do not describe the unsigned Alpha as signed.

## Native CI evidence

- `go test ./...` Windows and Ubuntu, Linux `go test -race ./...`, Windows `go vet ./...` and PE Windows GUI subsystem check.
- Actual native Security 4663 read-only query **PASS** on Windows runner. This proves Event Log access, not that a real file-write audit was produced.
- Real Win32 GUI agent launch/install/uninstall **PASS** on Windows runner, without reboot or real account sign-in.
- PowerShell script parse-only check **PASS** on Windows, but real certificate signature/verification is **not executable without a publisher certificate**.

**No claim of production-ready machine protection.**
