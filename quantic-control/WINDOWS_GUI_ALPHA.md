# Quantic Control — Windows native GUI Alpha (file integrity diagnostic)

A **Win32-native** laboratory executable, deliberately **independent from any web view, Electron, PowerShell, browser or hidden command terminal**.

## User workflow

1. Double-click `quantic-control-gui-alpha.exe` on Windows x64.
2. Choose **Choisir un fichier** with the standard Windows file picker (max. 32 MiB, only regular files).
3. The app computes a SHA-256 digest and retains the reference **in process memory only** for the current session.
4. Choose **Revérifier** to detect a change since the reference was taken. Changed/removed/unreadable files are reported without changing them.
5. Choose **Oublier** or close the app to discard the in-memory file reference.

There are no `draft-*.json` prompts, no new network connection, no registry modifications, no elevation, no resident background agent, no unsigned shell command execution. No sensitive content is uploaded. The app does not store the selected path or digest on disk.

## Scope and security

- This is an **explicit local diagnostic**, not an antivirus, anti-ransomware scanner, EDR, malware classifier, periodic monitoring service, authentication UI, remotely controlled console or durable protection agent.
- A clean result only means the current bytes match the reference seen earlier *in the same session*. It does not prove a file is trustworthy.
- It is possible for malicious code to evade this simple diagnostic or tamper with the process if the computer is compromised.
- Avoid running the program elevated and do not use on sensitive production computers as a security replacement.
- No Identity Vault private key is used by the GUI. The witness adapter and journal libraries remain separate behind future audited controls.

## Build

From `quantic-control/` on Windows x64 with Go 1.23:

    go build -ldflags="-H windowsgui" -o quantic-control-gui-alpha.exe ./cmd/quantic-control-gui

Go's Windows GUI linker subsystem flag suppresses a console window. CI verifies the PE subsystem equals `IMAGE_SUBSYSTEM_WINDOWS_GUI (2)`. The CI can compile and inspect PE headers but **cannot verify clicking and file selection in an interactive Windows desktop session**; real UX testing remains necessary.

The GitHub Actions unsigned executable is a **portable lab binary**, not a signed installer or deployable security product. It is intentionally separate from the older CLI and does not modify Windows security protections.
