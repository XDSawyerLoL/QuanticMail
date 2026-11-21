# Native Vault / Scattering / dual-authority laboratory
Frozen source import: 80 source files (291917 bytes) from the final dual authority laboratory, without generated executables, test private keys, databases or logs. Source manifest SHA256 74b9b495ff8e9089e5491642533348e2edd23bb47644e35915c2857204334ebe. Original git subtree after import f05adb633633ebb17c714d3c032ad9590a54e974. Exact subtree checked against independently constructed local git tree. Do not treat this lab as production or use real identities.
This folder is deliberately excluded from Next application lint and separately tested by the native lab workflow. Linux Go >=1.23, OpenSSL >=3.5 (ML-KEM-768 and ML-DSA-65), Python cryptography and Node runtime. CI compiles both native binaries from source; no unsigned prebuilt executable is downloaded. Image/dependency versions still need reproducibility/lockdown before production.
From this directory:
```sh
python3 verify_sources.py
(cd scattering/native && go build -trimpath -o ../QuanticNativePacer_v7_1_linux_amd64 .)
(cd vault && go test -tags pqopenssl ./... && go build -tags pqopenssl -o VaultIsolated-linux .)
node --test vault/tests/*.test.mjs scattering/compact-pacing.test.mjs
(cd vault && python3 -m unittest test_pq_dual_unit test_schedule_unit -v && python3 -u test_pq_dual_network.py)
```
The double authority binds full ML-KEM/ML-DSA public key pins to a device, a monotonic sequence and revocation; detached ML-DSA root proof is independently staged at each witness and combines with P-256 grant digest in 3-of-4 votes. Enrollment uses a pre-established root pin. Register feed remains 256/2048 bytes; separate proof distribution is not secured or automated by this lab. Older single-signature installations and the Go client missing explicit dual-mode pin remain open issues. Classical leases/TLS, simultaneous rollback, native Windows PQ, real account migration, production packaging, independent audit and physical network metadata tests remain open. CI failure is a blocker, not a reason to bypass tests. No automatic deployment. Review any source update and update SOURCE_SHA256.json to match; never modify the inventory just to suppress unexplained drift.
