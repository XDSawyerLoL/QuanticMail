# Quantic Pay: local automatic recovery service (LAB ONLY)

This entrypoint is a **process wrapper**, not a payment server, production
settlement engine, or a remote witness service. It supervises the already
implemented in-process experimental cross-shard recovery worker. It does not
create a live ledger, network transport, keys, or customer balances.

## Trust boundary and required adapter

`scripts/quantic-pay-recovery-agent-lab.mjs` loads a **trusted, locally
provisioned** ES module by the absolute path in `QUANTIC_PAY_RECOVERY_MODULE`.
The file must be owned by the process user and must not be writable by
groups/others on Unix. This is executable code, **not** a data-only config;
never load an adapter from email, a public URL, or a writable shared folder.

The module MUST export:

```js
export async function createRecoveryWorkerLab() {
  // Only use an independently reviewed local experimental configuration.
  // Provision the native private credentials, four witness objects on each
  // shard, certified durable ledgers and 11 destination validators here.
  // Return openCrossShardRecoveryWorkerLab({...});
}
```

The returned worker must implement `start()`, `close()`, `last()` and
`stats()`. Restart safety comes from rereading the **certified ledgers**, not
a plaintext cursor or a cached intent. The operator must protect all private
keys and journal directories, and must configure independent peer hosts before
making claims about independent witness security.

### Manual local start

```bash
export QUANTIC_PAY_RECOVERY_MODULE=/absolute/private/path/recovery-adapter.mjs
export QUANTIC_PAY_RECOVERY_HEARTBEAT_MS=10000
node scripts/quantic-pay-recovery-agent-lab.mjs
```

JSON records contain `ready`, `heartbeat`, and `stopped`. They report
counts and states, never private keys, payloads, or ledger contents. During
a temporary network interruption, `status: "deferred"` is expected: the
worker retries on subsequent ticks. Check the missing peer rather than
resetting its journal or synthesizing a new COMMIT decision.

### Linux: process restart with systemd user services

Save a user unit to
`~/.config/systemd/user/quantic-pay-recovery-lab.service`; substitute actual
absolute paths. Use a restricted environment file with permission 0600.

```ini
[Unit]
Description=Quantic Pay local recovery laboratory
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/home/USER/QuanticMail
EnvironmentFile=/home/USER/.config/quantic-pay-lab.env
ExecStart=/usr/bin/node /home/USER/QuanticMail/scripts/quantic-pay-recovery-agent-lab.mjs
Restart=always
RestartSec=5
NoNewPrivileges=yes
UMask=0077

[Install]
WantedBy=default.target
```

```bash
systemctl --user daemon-reload
systemctl --user enable --now quantic-pay-recovery-lab.service
journalctl --user -u quantic-pay-recovery-lab.service -f
```

A user service normally needs a logged-in session. Persistent startup across
logouts requires an operator-approved linger setting and a machine that stays
powered on. The unit alone does **not** supply availability SLAs.

### Windows: Task Scheduler

Create a protected local launcher under the intended non-admin user profile:

```cmd
@echo off
set "QUANTIC_PAY_RECOVERY_MODULE=C:\\QuanticPrivate\\recovery-adapter.mjs"
set "QUANTIC_PAY_RECOVERY_HEARTBEAT_MS=10000"
"C:\\Program Files\\nodejs\\node.exe" "C:\\QuanticMail\\scripts\\quantic-pay-recovery-agent-lab.mjs"
```

In Windows Task Scheduler, create a task for that launcher at user sign-in or
computer startup. Select **Do not start a new instance**, enable restart after
task failure, and run under a non-admin account with read access to the
trusted adapter and the necessary protected lab journals. Configure NTFS ACLs
and **do not** place private key material in the launcher. A stopped computer
cannot run this process.

## Witness repair and safety properties

The `pay-shard-witness-bridge-lab.mjs` adapter now exposes
`repairWitness(replica, witness, otherThreeWitnesses)` and
`repairLagging(replica, allFourWitnesses)`.

A lagging witness can catch up **only if**:

1. A 3/4 peer quorum independently signs the current tip using a fresh
   randomly generated challenge held inside the lagging witness.
2. The witness is idle, with no pending vote or conflicting lock.
3. Its locally stored checkpoint is a prefix of the certified shard chain.
4. Every intervening block and 11/16 financial QC independently verifies.
5. The final chain root equals the currently attested quorum root.

Partial restoration may leave a committed prefix, which can be advanced
again from a fresh quorum. A pending conflicting vote is **never cleared**.
The live worker attempts optional repair only after tip freshness succeeds.
If just two peers remain, it fails closed instead of creating new authority.

## Known limitations

- **Not monetary settlement**: all test amounts are simulated units.
- **Not Byzantine network availability**: the local worker needs a live
  majority, reachable peer processes and separately protected signing keys.
- **Not remote security**: local witness objects currently have no independently
  authenticated network RPC; four files on one machine are not four independent
  security domains.
- **Not protection from full host compromise**, arbitrary key extraction,
  loss of all witness journals, clock manipulation or simultaneous rollbacks
  of a 3/4 quorum.
- No automatic committee rotation or operational alert routing in this wrapper.
- No bank/payment rail/euro numérique integration or regulatory certification.

Before a real rollout, independently administer the witnesses, deploy mutual
TLS peer authorization, enforce key custody, monitor failed repairs, and
run external adversarial recovery drills.
