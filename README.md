# QuanticMail

QuanticMail is the mail product of Quantic Sillage.

The project aims to provide a fast, privacy-conscious webmail experience on custom domains such as `@sillage.com`, while remaining interoperable with standard email clients.

## Architecture

- **Web client:** Next.js / React / TypeScript
- **Mail API:** JMAP
- **Mail server target:** Stalwart (JMAP, SMTP, IMAP, CalDAV, CardDAV)
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

## Local configuration

Copy `.env.example` to `.env.local` and configure:

- `JMAP_SESSION_URL` — the JMAP discovery URL of the mail server
- `SESSION_SECRET` — a high-entropy secret of at least 32 characters

Real mailbox passwords, server administrator credentials, TLS keys and production tokens must never be committed to this repository.

## Next production milestone

Run Stalwart on production infrastructure, create the mail domain and accounts, then configure MX, SPF, DKIM, DMARC, TLS and PTR/rDNS before exposing the public QuanticMail service.
