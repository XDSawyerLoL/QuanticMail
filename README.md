# QuanticMail

QuanticMail is the mail product of Quantic Sillage.

The project aims to provide a fast, privacy-conscious webmail experience on a domain controlled by Quantic Sillage, while remaining interoperable with standard email clients.

## Architecture

- **Web client:** Next.js / React / TypeScript
- **Mail API:** JMAP
- **Mail server:** Stalwart (JMAP, SMTP, IMAP, CalDAV, CardDAV)
- **Identity:** QuanticMail by Quantic Sillage
- **Secrets:** never committed to Git; local and production configuration use environment variables / secret stores

## Current deployment

- **Web application:** `https://quanticmail.onrender.com`
- **Production mail domain:** configurable; do not use a domain until Quantic Sillage owns and controls it
- **Current brand-domain candidate:** `quanticsillage.com`

The web application and mail server are intentionally separate. Render hosts the Next.js application; Stalwart belongs on a dedicated VPS with SMTP port access, a dedicated public IP and configurable PTR/rDNS.

## V0.2 capabilities

- server-side JMAP authentication
- encrypted HttpOnly session cookie
- mailbox and folder discovery
- live message listing and reading
- folder switching and refresh
- local search across loaded messages
- message composition and JMAP submission
- logout, origin checks and basic abuse throttling

## V0.3 production tooling

- hardened production Stalwart Docker Compose
- VPS bootstrap script with firewall rules
- configurable mail-server hostname
- production topology and DNS checklist
- PTR/rDNS and deliverability requirements

See [`docs/V0.3-PRODUCTION.md`](docs/V0.3-PRODUCTION.md).

## Local configuration

Copy `.env.example` to `.env.local` and configure:

- `NEXT_PUBLIC_MAIL_DOMAIN` — a domain you control
- `JMAP_SESSION_URL` — the JMAP discovery URL of the mail server
- `SESSION_SECRET` — a high-entropy secret of at least 32 characters

Real mailbox passwords, server administrator credentials, TLS keys and production tokens must never be committed to this repository.
