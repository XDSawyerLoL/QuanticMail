# Native-only architecture — mandatory (2026-11-24)

Quantic Mail, Identity Vault and Quantic ID are installable native applications. No browser client, Electron website wrapper, legacy HTTP relay, hosted mailbox, or silent fallback is permitted in the target. Quantic Scattering and its authenticated native protocol are the transport target; do not infer that its production readiness is proven.

## Retirement stage 1
Normal legacy npm launch/build/release commands now fail closed. The old Hostinger static publication and Electron release workflows are inert and cannot write releases or branches. Historical code and protocol tests remain for migration analysis, not for deployment. Direct legacy desktop, Next configuration, relay CLI, static export, smoke CLI and VPS bootstrap now fail closed on this branch. Historical source is recoverable from Git history; migration libraries and synthetic protocol tests are retained. Previously deployed services, compose files and old binaries are NOT disabled by this change.

## Required before service shutdown / source removal
- Inventory Render, Railway, Hostinger, old static bundles, old releases, SMTP deployments and integrations. Do not publish or reopen old clients.
- Preserve encrypted backups and authoritative queues; do not delete browser stores, private keys, or accounts automatically.
- Independently verify native import of identity, keys, contacts, messages, prekeys, revocations, and pending deliveries; test restart, recovery and rollback. No real migration until the existing assurance gates are met.
- Revoke obsolete credentials and remove legacy DNS/routes/publication artifacts after verified cutover. Remove legacy runtime source and dependencies only after archival/migration approval. Verify no alternate route or fallback remains.
- Native installer must be signed and independently tested, including offline/failure behavior.

This change is a repository publication freeze, not live infrastructure shutdown, production certification or complete removal.
