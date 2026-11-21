# V7.1.4 — witness quorum laboratory (not production)

Run node --test tests/scattering-manifest-session.test.mjs tests/scattering-witness-authority.test.mjs. Local Node 22: 29/29 test cases passed (14 inherited and 15 new; includes expected failure boundary).

Four independently pinned Ed25519 witness keys; require 3 distinct signatures on the same signed manifest sequence and digest, linked to a fresh 256-bit challenge. Proof lifetime 10 seconds. Witness files are persisted synchronously, with single-writer assumption; directory durability under Windows not verified. The reader uses the actual QuanticMail manifest validator. No production account or private root key accessed.

After revocation reaches a quorum of three, a fresh query cannot authorize the prior state with at most one compromised witness, assuming honest witness state cannot roll back. After updating all four, rolling back one keeps the newer quorum; rolling back two denies authorization; rolling back three admits the old state on a fresh reader. Partial propagation, in-flight pre-revocation replies, availability, key custody, clock integrity, independent failure domains and real network communication remain unvalidated. Four local files on one machine are NOT independent infrastructure. Not a distributed consensus protocol. The 10-second proof limit is not an established end-to-end revocation SLA. No post-quantum security claim.

Next: independently durable witnesses, committed update protocol/convergence, encrypted fixed-size control traffic, audited handshake and native V7.1.1 transport integration. Do not deploy on real identities. Track broader MITRE ATT&CK and OWASP ASVS coverage, supply chain, endpoints, API/auth, side channels and combined adversarial tests.
