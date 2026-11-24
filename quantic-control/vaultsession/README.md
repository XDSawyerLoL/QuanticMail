# Sentinel / native Identity Vault proof bridge

This component checks possession of an independently pinned native Vault ML-DSA-65 device key, using the existing pq-proof-lab wire request and exact pqKeys.proof payload. It does not export the private key, create a second identity or invent a generic signing operation.

A fresh random 256-bit nonce is bound to the Sentinel machine label and hashed to form the challenge. One successful response is accepted per challenge, for less than 30 seconds. The identity's address, device ID, ML-KEM pin and ML-DSA SPKI SHA-256 pin must be supplied by an independently trusted enrollment. No trust-on-first-use or fallback signature algorithm is allowed. The OpenSSL verifier is enabled only with cgo and pqopenssl; all other builds refuse authentication.

The machine label in the challenge is not hardware attestation. This protocol proves key possession; it does not prove a particular human approved a particular administrative action, provide revocation, or authorize process termination, file blocking or policy changes. Relay resistance depends on a trusted broker channel and enrollment. It must not be treated as an administrative authorization protocol.

The interoperability workflow checks actual source at native Vault revision 337a8311f0a980a5dd61520555465ea06d18552c. It calls the existing pqKeys.proof method using synthetic keys and verifies the result in the new Sentinel package. The method is the signing primitive used by the existing native broker, not the complete authenticated broker transport or encrypted persistent vault lifecycle.

Still required: independent enrollment and pin distribution; trusted authenticated local broker transport with explicit user approval and revocation; actual UI/session integration; signed policy format and authorization verification; packaging and trusted OpenSSL dependencies. The existing unsigned Windows Sentinel GUI does not yet use this package. No new production executable or active protection is claimed.
