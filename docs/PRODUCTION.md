# QuanticMail production runbook

## Target architecture

- Web client/API: Render, Frankfurt — `https://quanticmail.onrender.com`
- Public product domain target: `quanticsillage.com`
- Mail host target: `mail.quanticsillage.com`
- Mail core: Stalwart `v0.16` on a dedicated Linux VPS
- First mailbox target: `valentin.hernandez@quanticsillage.com`

> `quanticsillage.com` must be purchased and controlled before DNS or public mail can be activated. Do not use `sillage.com`: it is already registered and in use by a third party.

## VPS requirements

Use a provider that gives the server:

1. A dedicated public IPv4 address.
2. The ability to set reverse DNS / PTR for that IP to `mail.quanticsillage.com`.
3. Inbound TCP 25, 443, 465, 587, 993 (plus optional 143, 110, 995, 4190).
4. Outbound TCP 25 without provider blocking.
5. Persistent disk storage.
6. A clean IP reputation; avoid recycled IPs on email blocklists.

The web app and the mail core are deliberately separate. Render hosts the Next.js product, while the mail core must run on infrastructure that supports SMTP and reverse DNS.

## Server bootstrap

Install Docker Engine and Docker Compose on the VPS, then clone this repository and run:

```bash
cp .env.mail.example .env.mail
docker compose --env-file .env.mail -f docker-compose.mail.yml up -d
docker logs quanticmail-stalwart 2>&1 | grep -A8 'bootstrap mode'
```

The bootstrap administrator password is temporary. Complete the setup wizard through an SSH tunnel to the loopback-only port 8080:

```bash
ssh -L 8080:127.0.0.1:8080 root@SERVER_IP
```

Then open `http://127.0.0.1:8080/admin` locally.

## Stalwart wizard values

- Server hostname: `mail.quanticsillage.com`
- Default email domain: `quanticsillage.com`
- TLS: enabled
- DKIM signing keys: enabled
- Storage: RocksDB/local storage for the initial single-node deployment
- Directory: internal directory for V0.3
- DNS management: manual until the DNS provider is connected

After the wizard completes, restart Stalwart:

```bash
docker compose --env-file .env.mail -f docker-compose.mail.yml restart stalwart
```

The production administration endpoint should then be `https://mail.quanticsillage.com/admin`.

## DNS order of operations

Do not publish MX until the server is online and the mail hostname resolves correctly.

1. Create `A mail.quanticsillage.com -> SERVER_IPV4`.
2. Ask the VPS provider to set `PTR SERVER_IPV4 -> mail.quanticsillage.com`.
3. Confirm forward/reverse symmetry: `mail.quanticsillage.com` resolves to the same IP and that IP reverses to `mail.quanticsillage.com`.
4. Complete Stalwart setup and retrieve the generated DNS zone from the domain management page.
5. Publish the generated DKIM, SPF, DMARC, MX, MTA-STS, TLS-RPT, SRV/autoconfig records.
6. Wait for DNS propagation and verify externally.
7. Only then create/use production mailboxes.

A starter template is provided in `docs/dns-template.txt`, but Stalwart's generated zone is authoritative for DKIM selectors and final policy values.

## First mailbox

Create an individual account in Stalwart:

- Display name: Valentin Hernandez
- Primary email: `valentin.hernandez@quanticsillage.com`

Use a unique high-entropy password. Do not store the password in GitHub, `.env`, issues, build logs, or source files.

## Connect QuanticMail web

Render must have these runtime variables:

```text
NEXT_PUBLIC_APP_NAME=QuanticMail
NEXT_PUBLIC_MAIL_DOMAIN=quanticsillage.com
JMAP_SESSION_URL=https://mail.quanticsillage.com/.well-known/jmap
SESSION_SECRET=<high-entropy secret>
```

Once the JMAP endpoint is live, users authenticate through the QuanticMail login form using their mailbox credentials. Credentials stay inside the encrypted HttpOnly application session and are not committed to Git.

## Production checks

Before declaring the service live:

- HTTPS certificate valid for `mail.quanticsillage.com`.
- JMAP session discovery responds over HTTPS.
- SMTP port 25 reachable externally.
- Submission ports 465/587 reachable.
- IMAPS 993 reachable if third-party clients are supported.
- MX points only to active mail servers.
- SPF passes.
- DKIM passes for outbound mail.
- DMARC alignment passes.
- PTR/rDNS matches the SMTP hostname.
- Test delivery to at least Gmail, Outlook and Proton Mail.
- Test inbound mail from external providers.
- Confirm the server is not an open relay.
- Back up both Stalwart persistent Docker volumes.
