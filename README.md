# QuanticMail

QuanticMail is the mail product of Quantic Sillage.

The project aims to provide a fast, privacy-conscious webmail experience on custom domains such as `@sillage.com`, while remaining interoperable with standard email clients.

## Architecture

- **Web client:** Next.js / React / TypeScript
- **Mail API:** JMAP
- **Mail server target:** Stalwart (JMAP, SMTP, IMAP, CalDAV, CardDAV)
- **Identity:** QuanticMail by Quantic Sillage
- **Secrets:** never committed to Git; local and production configuration use environment variables / secret stores

## Product direction

The first milestone is a usable webmail client: authentication, inbox, message reading, folders, search and composition. The transport and storage layer stays replaceable so QuanticMail is not locked to a single provider.

## Status

Initial project bootstrap.
