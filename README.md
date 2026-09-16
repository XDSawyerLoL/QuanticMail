# QuanticMail

QuanticMail is the mail product of Quantic Sillage.

The project aims to provide a fast, privacy-conscious webmail experience on custom domains such as `@quanticsillage.com`, while remaining interoperable with standard email clients.

## Architecture

- **Web client:** Next.js / React / TypeScript
- **Mail API:** JMAP
- **Mail server:** Stalwart (JMAP, SMTP, IMAP, CalDAV, CardDAV)
- **Identity:** QuanticMail by Quantic Sillage
- **Secrets:** never committed to Git; local and production configuration use environment variables / secret stores

## V0.2 capabilities

- server-side JMAP authentication
- encrypted HttpOnly session cookie
- mailbox and folder discovery
- live message listing and reading
- folder switching and refresh
- local search across loaded messages
- message composition and JMAP submission
- logout, origin checks and basic abuse throttling

## V0.3 production target

- Web application: `https://quanticmail.onrender.com`
- Mail domain target: `quanticsillage.com`
- Mail host target: `mail.quanticsillage.com`
- First mailbox target: `valentin.hernandez@quanticsillage.com`

The public domain must be purchased and controlled before production DNS can be activated. `sillage.com` is not used because it is already registered and active outside this project.

See [`docs/PRODUCTION.md`](docs/PRODUCTION.md) for the VPS, DNS, PTR/rDNS, Stalwart setup and production checklist.

## Local configuration

Copy `.env.example` to `.env.local` and configure:

- `JMAP_SESSION_URL` — the JMAP discovery URL of the mail server
- `SESSION_SECRET` — a high-entropy secret of at least 32 characters

Real mailbox passwords, server administrator credentials, TLS keys and production tokens must never be committed to this repository.
