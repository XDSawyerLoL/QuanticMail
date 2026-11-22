# Quantic Sillage — five security findings: technical remediation gates

Date: 2026-11-22. **Branch only, not a deployment or a penetration test.**
Do not merge PR #48 wholesale or move an actual identity/payment on the
strength of a green CI. Explicitly preserve live mail, accounts, prekeys and
historical root material until the recovery procedure is proven.

## P0: Browser private keys and bearer tokens

**Status: OPEN, NOT REMEDIATED.** `lib/quantic/local-db.ts` still uses
IndexedDB for exportable private JWKs, postquantum private material,
outstanding one-time prekeys and bearer tokens. A compromised same-origin
script or endpoint OS can read these. A Content-Security-Policy, encrypted
archive or a successful native Go test does NOT make a browser key
nonexportable or hardware-backed.

Acceptance requires: a separately authenticated, trusted local/native
process that holds or uses nonexportable key material, independent
user-visible approval for signing, strict replay/intent binding, and a
compatible multi-device root trust model. Browser rendering code must never
receive raw signing/decryption keys or device bearer tokens. Verify
negative tests with malicious web-origin JS. Existing compromised root
keys cannot be made secret retroactively merely by moving them.

Existing read-only `.qma` export and offline native verification do
not satisfy this P0. Do not delete original keys or claim full protection.

## P0: Real identity migration

**Status: VERIFIED READ-ONLY PRECONDITIONS, LIVE CUTOVER OPEN.**
The six-store snapshot captures identity, paired devices, prekeys, local
messages, contacts and outbox; it deliberately excludes live bearer
tokens, rejects incomplete exports and can be checked with the independent
historical root SPKI pin. The offline lab exercises actual P-256, ML-KEM
and ML-DSA key operations and verifies signed historical records.

This is not a live account transfer. Required acceptance sequence:
1. Offline backup verified separately with historical root pin and
   source-side record-for-record reconciliation; keep original intact.
2. Native device key ownership proved locally with actual user consent
   and a new signed enrollment; independent registry/manifest re-read.
3. Native client proves historical ciphertext recovery, replays no old
   prekey or pending outbox automatically, and obtains **new** auth tokens.
4. Authenticated bidirectional message send/pull/ack and old/new-device
   continuity on the trusted real relay and on physical Windows hardware.
5. Explicit opt-in, atomic cutover/recovery, independent audit of
   concurrent tabs and registry stale caches; only then revoke the old
   device. Preserve offline historical archive under an approved retention
   policy. Do not automatically delete historical root keys.

No production identity was migrated or erased in this PR.

## P1: Process-local Web relay versus durable standalone relay

**Status: FAIL-CLOSED CUTOVER ROUTING IMPLEMENTED, ACTIVATION BLOCKED.**
`lib/quantic/durable-web-relay-route.mjs` and Next `proxy.ts`
route 13 core identity/mail/device operations to exactly one HTTPS
relay only when both environment gates are satisfied:

```
QUANTIC_WEB_DURABLE_RELAY_ORIGIN=https://<independently-reviewed-relay>
QUANTIC_WEB_DURABLE_RELAY_READY=1
```

On the independently administered relay host also set:
```
QUANTIC_RELAY_REQUIRE_POSTGRES=1
QUANTIC_RELAY_DATABASE_URL=postgresql://<privately-provisioned-DSN>
```

The backend now fails on startup when the explicit PostgreSQL-only
switch is enabled without a database. No database URI or password may
be committed to GitHub or included in error reports.

Production requests otherwise receive HTTP 503, no process-local storage
fallback; development intentionally retains the old flow for compatibility.
Browser cookies, Origin and spoofable forwarding headers are not sent to
the remote service; only bearer authentication, Accept and Content-Type
are forwarded. External rewriters must not use these URLs for SSRF.

**Before enabling the ready flag:** review the standalone relay's
PostgreSQL durability, its authoritative registry and device manifest
checks, linked-device revocation, existing identity roster, backup and
restore. Validate existing users against imported signed records using
freshly authorized credentials. A memory-only Render process cannot be
assumed to contain a recoverable or migratable persistent identity
database. Export historical client-side identity and mail archives
first; never invent the server's lost state. Perform staging failover,
database restart, two-instance CAS contention and recovery exercises,
then enable the ready flag in a controlled rollout. No Render production
environment variable is changed by this branch.

**Important:** fail-closed means that merging without provisioning the
durable relay and verifying user migration will intentionally deny those
API operations. Preserve the current live service until migration and
rollback drills pass.

The standalone relay's send, pull, ack and receipts now enforce an
active signed-manifest device check, including recipient eligibility,
before changing durable messages. This is narrower than a complete
object-level authorization and penetration audit.

## P1: Physical independence of payment witnesses

**Status: OPEN, AUTOMATED MULTI-PROCESS LAB VERIFIED.**
Four/eight Node processes with distinct mTLS certs, persistent journals
and signing keys on the same GitHub Actions machine are **not** different
failure domains. Use at least four hosts with independently administered
accounts, keys, storage, network paths and fault injection *per shard*,
with independent device/key custody evidence. Remote server certificates
and 3/4 signed checkpoints attest protocol identity, not physical
separation. See `docs/quantic-pay-multihost-readiness-lab.md`.

Measure actual WAN partitions, 2/2 split, simultaneous host rollback,
key compromise, clock drift and storage replays. No synthetic operation
permits issuing, moving or redeeming real money.

## P1: Windows package, signing and native key custody

**Status: RUNTIME VERSION GAP MITIGATED, RELEASE/CUSTODY OPEN.**
The obsolete Electron 38 dependency was raised to **45.4.1**, with an
explicit binary probe verifying that actual Electron embeds Node >=24.
The CI and manual Windows release workflows require this probe. The
native Windows mode must keep its Node >=24 guard; never bypass it.

The installer continues to require trusted independent hashes, valid
Authenticode publisher certification and review before distribution.
The repository does **not** provide a publisher code-signing certificate
or hardware-backed escrow by itself, and no signature is synthesized.
Windows ACLs, an encrypted software vault, mTLS, and temporary PEM
buffer wiping cannot survive OS administrator or process-memory
compromise. A separate optional TPM/HSM or independent custody design
and real-device tests are required for strong key-extraction resistance.
No Windows production release, automatic migration or live credentials
are authorized by the change.

## Operational acceptance

- CI green for both general JS/TS, real Windows Electron, native Windows
  PQ Go and native Linux suites, **for the exact head commit**.
- Independent security review and targeted fuzz/penetration tests.
- Live system health and actual deployed commit independently checked.
- Recoverable backup and rollback rehearsed before irreversible action.
- Two-person signoff for migration/deploy, with no secret material in CI
  artifacts, GitHub issues or public repositories.
