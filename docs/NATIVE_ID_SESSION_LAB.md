# Quantic ID: certificate-bound native session (private laboratory)

The relying party now performs an actual server-side login, not just receipt
verification. It issues its own random one-shot nonce. The native client
obtains fresh proofs from the four independent authority services using that
nonce. Three or four distinct matching signed authentication receipts are
required. The relying party independently verifies the enrolled candidate,
trusted authority keys, client certificate fingerprint, nonce, and receipt
freshness before opening a session.

The only protected operation is whoami (synthetic address and device ID).
The session is memory-only, limited to 60 seconds, bound to the pinned mTLS
certificate and a random session identifier. It does not survive a server
restart. A session identifier or copied receipts alone are insufficient.
No production mailbox, payment, legacy account or public endpoint is enabled.

The native desktop adapter createWindowsNativeSessionClientLab uses the
existing graphical Windows proof operation. The trusted UI must call lock()
on explicit lock, application exit or OS lock. Local access is invalidated
before network I/O; if the remote request fails, remote closure is NOT
confirmed and the server's 60-second expiry is the remaining boundary.
There is no automatic renewal. OS event wiring and interactive Windows
validation are not yet delivered.

The service listens on loopback only. Operators must supply independently
authenticated TLS material and preapproved enrollment receipts. The service
does not fabricate operator independence or issue production credentials.
The tests use four local HTTPS authority services with separate signing
keys and synthetic device keys. They cover protected lookup, refusal before
login, replay, wrong client certificate, expiry, clock rollback, explicit
lock, restart and 3-of-4 versus 2-of-4 availability.

Run on Linux with Node 24 and OpenSSL:
    node --experimental-transform-types --test tests/native-owner-candidate.test.mjs

No claims of physical-host or production validation.
