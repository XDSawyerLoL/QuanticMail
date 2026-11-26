# Quantic Sentinel + Microsoft Defender CFA — source-of-truth and safe response

## What was added

**Local, read-only integration with Windows Defender's existing Controlled Folder Access (CFA) events**, not a newly invented antivirus sensor.

- Native Windows Event Log reader: direct `wevtapi.dll` `EvtQuery`, `EvtNext`, `EvtRender`, `EvtClose`. No PowerShell, subprocesses, remote polling, rights elevation or changes to Defender settings.
- Fixed local channel: `Microsoft-Windows-Windows Defender/Operational`.
- Bounded query: up to 64 recent event records (plus one record to detect incomplete coverage), rendered as at most 64 KiB of UTF-16 XML each, polled every 10 seconds while the user-mode resident agent is running.
- Relevant event IDs ([Microsoft Learn](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-windows-events)): **1123** CFA write blocked, **1124** CFA write audited, **1127** sector-write blocked, **1128** sector-write audited.
- The XML parser requires the correct Defender provider, event channel, ID, nonzero record ID, and timestamp. Only **explicit named EventData fields** may identify a process path or PID. **Never attribute the `System.Execution ProcessID` to the offending application**: it can identify the Windows logging provider instead.
- The local persistent audit includes the exact event ID/outcome, Defender-reported executable path if supplied, Defender-reported target path if supplied, and a cautious correlation to the selected Sentinel folder and a recent file-activity burst (within 30 seconds).
- The GUI's **Historique local** shows this evidence and a conservative next step. **Protection antirançongiciel Windows** merely opens the Microsoft Windows Security controls already installed.

## Scope of correlation

A file scanner watching metadata cannot establish **which process wrote a file**. Our correlation only describes whether the independently recorded Defender target is within the explicitly watched directory and whether a Sentinel burst was reported at nearly the same time. It is *temporal/contextual proximity*, not proof of causation or proof that the user is under attack.

A Defender **blocked** event indicates that Defender, not Quantic Sentinel, reported blocking a particular attempt. An **audited** event indicates a rule was triggered in audit mode; the action may have been allowed. They must never be presented as equivalent.

No automated process killing, adding AV exclusions, deleting files, changing firewall rules, disabling protection or silent isolation. A safe response is **show the actual event evidence and ask the user to inspect Windows Security settings and the application involved**.

## Failure and privacy

- Missing, disabled or restricted Defender Event Log: a `defender_unavailable` record is written. The app does **not** report full protection or secretly enable Defender. On recovery it emits `defender_restored`.
- The native query retrieves recent records only and intentionally skips pre-agent historical events. If more than 64 events are visible, an `defender_incomplete` warning is logged. Excess events can be missed; event log clears or floods must not result in a false security guarantee.
- No network upload, no file content reads, no cloud telemetry. Program paths and target paths can reveal sensitive filenames, so they are retained only in the locally stored bounded audit. They are **not tamper-proof** against software with the same user's rights.
- Missing process/target fields are explicitly reported as unavailable; no process identity is fabricated from `System.Execution` metadata.
- **Windows CFA protection only works when configured and active**, with machine policy and security feature requirements that Sentinel does not control.
- Only the lab agent built from PR #74 is wired to this feature. There is still no signed installer, independent production security audit, rollback-safe Event Log offset, tamper-resistant process telemetry, true prevention engine or authenticated policy updates from Identity Vault.

## Verification

Automated portable tests: synthetic Microsoft Defender XML with source validation, spoofed-provider rejection, altered IDs, missing PID, named EventData PID handling, path boundary checks, contextual 30-second window, polling deduplication, stale event exclusion, log-source failure/recovery and a resident-agent simulated Defender event persisted to JSONL.

Windows CI also invokes the real native `EvtQuery` API in read-only mode. If the runner does not provide the Defender Operational channel, that test reports **SKIPPED**, not "live CFA events verified". **No ransomware is executed or simulated.** Do not claim real-world prevention effectiveness or PID attribution without real source fields.

## Next reliability gates

1. Validate parsing against actual **redacted Event Log XML** from Windows 10 and 11 with CFA auditing and blocks. Verify each field naming/availability in the native provider.
2. Confirm monitoring and continuation on an installed per-user agent after sign-out/in using a disposable Windows VM, and conduct safe file-creation/deletion tests without malicious payloads.
3. Test missing/locked/disabled Event Log, log rotation and event floods; define a durable, anti-replay event bookmark and clear-log recovery.
4. For process-to-file causal attribution, research/test independently sourced kernel/ETW telemetry or integrate approved endpoint-protection capabilities rather than guessing from temporal proximity.
5. Add a signed, user-approved and reversible response policy before implementing any action on processes or network access.
