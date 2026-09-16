# QuanticMail architecture

## Goal

QuanticMail is a first-party webmail product for Quantic Sillage. It must support custom domains, work with standard mail clients, and remain deployable without locking the product to a single SaaS mail provider.

## Components

### 1. QuanticMail Web

Next.js application responsible for:

- mailbox navigation
- message list and reader
- search
- compose/reply/forward flows
- account and settings UI
- authenticated calls to the QuanticMail server layer

The browser must never receive infrastructure administrator credentials.

### 2. Session/API layer

Server-side routes will own user sessions and JMAP authorization. The next milestone will add:

- login/logout
- encrypted, HttpOnly session cookies
- JMAP session discovery
- Mailbox/get, Email/query and Email/get
- EmailSubmission/set for sending mail
- CSRF and rate-limit protections

### 3. Mail core

Target server: Stalwart.

QuanticMail uses JMAP as its primary application protocol. SMTP and IMAP remain enabled for interoperability with Outlook, Apple Mail, Thunderbird and mobile clients.

### 4. Domain and deliverability

A production domain requires correct DNS and reputation configuration, including:

- MX
- SPF
- DKIM
- DMARC
- TLS certificates
- PTR/rDNS on the outbound mail IP
- abuse and postmaster handling

The repository does not contain domain secrets, private keys or production credentials.

## Deployment stages

1. Local web UI with sample messages.
2. Local Stalwart + real JMAP mailbox.
3. Authenticated QuanticMail sessions and real inbox/send flows.
4. Production DNS + `mail.<domain>` deployment.
5. Contacts, calendar, aliases, rules and administration.
6. Multi-tenant/business accounts if required.
