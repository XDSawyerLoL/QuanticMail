# Quantic Relay Standalone Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a standalone, durable Quantic Relay V1 that runs without Next.js or Render and preserves relay state across complete process restarts.

**Architecture:** Keep `lib/quantic/relay.ts` as the single protocol/crypto engine, add an explicit versioned snapshot/restore boundary, then place a native Node.js HTTP adapter and atomic JSON store around it. All mutating requests are serialized through a runtime transaction queue; successful and protocol-error mutations are persisted before the HTTP response, while disk-write failure rolls the in-memory engine back to the last durable snapshot.

**Tech Stack:** Node.js 22, TypeScript 5.9, native `node:http`, native `node:fs/promises`, native `node:crypto`, Node test runner, existing Quantic Relay Protocol V1.

**Spec:** `docs/superpowers/specs/2026-09-16-quantic-relay-standalone-design.md`

## Global Constraints

- Reuse `lib/quantic/relay.ts`; do not create a second implementation of identity/device/message cryptography.
- Preserve `handle~fingerprint@quantic` as the canonical identity format.
- Default host is `127.0.0.1`, default port is `8787`, default data directory is `./data`.
- External Internet exposure still requires HTTPS via a reverse proxy; plaintext HTTP is for loopback/local development only.
- Persist only public identity/device metadata, encrypted envelopes, receipts, challenges, and rate-limit metadata; never persist private keys, vault passwords, or plaintext messages.
- Durable state format is `quantic-relay-state`, version `1`.
- A mutating request is not acknowledged until its resulting state is durably written.
- Mutations are serialized so snapshots cannot be committed out of order.
- If durable writing fails, restore the in-memory state that preceded the mutation.
- If a protocol operation throws after mutating state (for example, consuming a challenge), persist that resulting state before returning the protocol error.
- Corrupt or unsupported state files abort startup; never silently replace them with an empty relay.
- Do not add Express, Fastify, SQLite, or another server/storage dependency in this tranche.
- Existing `npm test`, `npm run build`, and `npm run lint` must remain green under the repository CI Node.js 22 environment.

---

### Task 1: Versioned relay state snapshot and restore

**Files:**
- Modify: `lib/quantic/relay.ts`
- Create: `tests/relay-state.test.ts`

**Interfaces:**
- Produces: `export type RelayPersistentState`
- Produces: `export function createEmptyRelayState(savedAt?: string): RelayPersistentState`
- Produces: `export function exportRelayState(savedAt?: string): RelayPersistentState`
- Produces: `export function restoreRelayState(input: unknown, nowMs?: number): void`
- Later tasks use these functions as the only persistence boundary around the internal `Map`/`Set` state.

- [ ] **Step 1: Write failing snapshot tests**

Create `tests/relay-state.test.ts` with tests that:

```ts
import assert from "node:assert/strict";
import test from "node:test";
import {
  createEmptyRelayState,
  exportRelayState,
  restoreRelayState,
} from "../lib/quantic/relay.ts";

test("empty relay state is explicit and versioned", () => {
  restoreRelayState(createEmptyRelayState("2026-09-16T00:00:00.000Z"));
  const snapshot = exportRelayState("2026-09-16T00:00:01.000Z");
  assert.equal(snapshot.format, "quantic-relay-state");
  assert.equal(snapshot.version, 1);
  assert.deepEqual(snapshot.identities, []);
  assert.deepEqual(snapshot.aliases, []);
  assert.deepEqual(snapshot.devices, []);
  assert.deepEqual(snapshot.queues, []);
  assert.deepEqual(snapshot.receipts, []);
});

test("relay state round-trips through JSON without Map or Set loss", () => {
  const state = createEmptyRelayState("2026-09-16T00:00:00.000Z");
  state.aliases = [["alice", ["alice~0123456789@quantic"]]];
  restoreRelayState(JSON.parse(JSON.stringify(state)));
  assert.deepEqual(exportRelayState().aliases, state.aliases);
});

test("unknown state format or version is rejected", () => {
  assert.throws(() => restoreRelayState({ format: "wrong", version: 1 }), /format/i);
  assert.throws(() => restoreRelayState({ format: "quantic-relay-state", version: 2 }), /version/i);
});
```

Add focused cases for malformed top-level arrays and duplicate map keys so corrupt JSON cannot create ambiguous internal state.

- [ ] **Step 2: Run the state tests and verify RED**

Run:

```bash
node --experimental-strip-types --test tests/relay-state.test.ts
```

Expected: FAIL because the three persistence exports do not exist.

- [ ] **Step 3: Implement the explicit JSON state type and deep snapshot**

In `lib/quantic/relay.ts`, add a JSON-safe type whose fields are arrays rather than implicit `Map`/`Set` serialization:

```ts
export type RelayPersistentState = {
  format: "quantic-relay-state";
  version: 1;
  savedAt: string;
  identities: Array<[string, IdentityRecord]>;
  aliases: Array<[string, string[]]>;
  challenges: Array<[string, ChallengeRecord]>;
  devices: Array<[string, DeviceRecord]>;
  queues: Array<[string, RelayEnvelope[]]>;
  receipts: Array<[string, DeliveryReceipt[]]>;
  sendWindows: Array<[string, number[]]>;
};
```

`exportRelayState()` must return a deep JSON-compatible copy, not references to live maps. Implement the copy by constructing the explicit object and round-tripping only that object through JSON, or by cloning every record/array before returning it.

`createEmptyRelayState()` returns all arrays empty and an ISO `savedAt`.

- [ ] **Step 4: Implement strict restore and expiration cleanup**

`restoreRelayState(input, nowMs)` must:

1. require a non-null object;
2. require `format === "quantic-relay-state"`;
3. require `version === 1`;
4. require every collection field to be an array of two-element entries;
5. reject duplicate keys for `identities`, `aliases`, `challenges`, `devices`, `queues`, `receipts`, and `sendWindows`;
6. reconstruct new `Map` and `Set` instances rather than mutating old maps in place;
7. remove challenges whose `expiresAt < nowMs`;
8. remove queued envelopes and receipts older than `MESSAGE_TTL_MS`;
9. remove send-window timestamps older than 60 seconds;
10. replace every internal collection only after the full snapshot validates, so a rejected restore cannot partially corrupt the current relay.

Because `state` is currently a stable object stored on `globalThis`, make its collection properties assignable or replace their contents only after building a fully validated temporary `RelayState`.

- [ ] **Step 5: Add expiration and failed-restore tests**

Add tests proving:

```ts
test("restore prunes expired transient data", () => {
  const now = Date.parse("2026-09-16T12:00:00.000Z");
  const state = createEmptyRelayState();
  state.challenges.push(["alice~0123456789@quantic", {
    challenge: "expired",
    handle: "alice",
    canonicalAddress: "alice~0123456789@quantic",
    fingerprint: "0123456789",
    publicKey: { kty: "EC", crv: "P-256", x: "x", y: "y" },
    signingPublicKey: { kty: "EC", crv: "P-256", x: "x", y: "y" },
    expiresAt: now - 1,
  }]);
  restoreRelayState(state, now);
  assert.deepEqual(exportRelayState().challenges, []);
});
```

Also snapshot a known valid state, attempt an invalid restore, and verify the previously valid state is unchanged.

- [ ] **Step 6: Run the focused test and full existing suite**

Run:

```bash
node --experimental-strip-types --test tests/relay-state.test.ts
npm test
```

Expected: PASS.

- [ ] **Step 7: Commit Task 1**

```bash
git add lib/quantic/relay.ts tests/relay-state.test.ts
git commit -m "feat: add durable relay state snapshots"
```

---

### Task 2: Atomic file store and serialized durable runtime

**Files:**
- Create: `standalone-relay/storage.ts`
- Create: `standalone-relay/runtime.ts`
- Create: `tests/relay-storage.test.ts`
- Create: `tests/relay-runtime.test.ts`

**Interfaces:**
- Consumes: `RelayPersistentState`, `exportRelayState`, `restoreRelayState` from Task 1.
- Produces: `export type RelayStateStore = { load(): Promise<RelayPersistentState | null>; save(state: RelayPersistentState): Promise<void> }`
- Produces: `export function createFileRelayStateStore(dataDir: string): RelayStateStore`
- Produces: `export class RelayRuntime` with `initialize()`, `read<T>(operation)`, `mutate<T>(operation)`, and `flush()`.

- [ ] **Step 1: Write RED tests for atomic storage**

Create `tests/relay-storage.test.ts` using `mkdtemp()` and `tmpdir()`:

```ts
test("file store returns null when no state file exists", async () => {
  const dir = await mkdtemp(join(tmpdir(), "quantic-relay-"));
  const store = createFileRelayStateStore(dir);
  assert.equal(await store.load(), null);
});

test("file store persists and reloads versioned state", async () => {
  const dir = await mkdtemp(join(tmpdir(), "quantic-relay-"));
  const store = createFileRelayStateStore(dir);
  const state = createEmptyRelayState("2026-09-16T00:00:00.000Z");
  await store.save(state);
  assert.deepEqual(await store.load(), state);
});
```

Add a test that writes invalid JSON to `relay-state.json` and expects `load()` to reject rather than returning `null`.

- [ ] **Step 2: Run storage tests and verify RED**

```bash
node --experimental-strip-types --test tests/relay-storage.test.ts
```

Expected: FAIL because the file store does not exist.

- [ ] **Step 3: Implement atomic `relay-state.json` writing**

`standalone-relay/storage.ts` must use:

```ts
const statePath = join(dataDir, "relay-state.json");
const tempPath = join(dataDir, `.relay-state.${process.pid}.${randomUUID()}.tmp`);
```

For `save(state)`:

1. `mkdir(dataDir, { recursive: true, mode: 0o700 })`;
2. open the temp path with restrictive `0o600` permissions;
3. write `JSON.stringify(state, null, 2) + "\n"`;
4. call `filehandle.sync()`;
5. close the handle;
6. rename the temp file to `relay-state.json` in the same directory;
7. if any step before rename fails, close if necessary, remove the temp file with `{ force: true }`, and rethrow.

For `load()`, return `null` only on `ENOENT`; JSON parse errors must propagate with an error naming the state path.

- [ ] **Step 4: Test that a failed temporary write preserves the existing final file**

Make the store factory accept an optional narrow filesystem adapter only for deterministic tests:

```ts
type RelayFs = Pick<typeof import("node:fs/promises"), "mkdir" | "open" | "readFile" | "rename" | "rm">;
createFileRelayStateStore(dataDir: string, fsApi = fsPromises)
```

Inject an adapter whose `rename` throws, then verify the previous `relay-state.json` content remains unchanged.

- [ ] **Step 5: Write RED runtime tests for serialization and rollback**

Create an in-memory fake store that records saves and can delay/reject them. Tests must prove:

```ts
test("mutations are durably serialized in request order", async () => {
  // First save is held until the test releases it.
  // Start mutation A and mutation B without awaiting A.
  // Assert B's operation has not executed while A's save is pending.
  // Release A, then assert B executes and a later snapshot is saved second.
});

test("disk failure restores the pre-mutation relay state", async () => {
  // Initialize an empty relay, make store.save reject,
  // mutate by creating a valid challenge,
  // expect rejection and assert the exported state has no challenge.
});
```

- [ ] **Step 6: Implement `RelayRuntime` transaction semantics**

The runtime keeps a single promise tail. `read()` first awaits the settled tail so reads never observe an in-memory mutation before its durability decision.

`mutate(operation)` runs only after the prior tail settles:

```ts
const before = exportRelayState();
let result: T | undefined;
let operationError: unknown;
try {
  result = operation();
} catch (error) {
  operationError = error;
}
const after = exportRelayState();
try {
  await store.save(after);
} catch (storageError) {
  restoreRelayState(before);
  throw storageError;
}
if (operationError) throw operationError;
return result as T;
```

This intentionally persists protocol side effects that happen before a `RelayError` (for example a consumed challenge) while rolling back only when durability itself fails.

`initialize()` loads the store, restores it if present, or restores `createEmptyRelayState()` if absent. `flush()` waits for the mutation tail and saves the current exported snapshot.

- [ ] **Step 7: Run storage/runtime tests and full suite**

```bash
node --experimental-strip-types --test tests/relay-storage.test.ts tests/relay-runtime.test.ts
npm test
```

Expected: PASS.

- [ ] **Step 8: Commit Task 2**

```bash
git add standalone-relay/storage.ts standalone-relay/runtime.ts tests/relay-storage.test.ts tests/relay-runtime.test.ts
git commit -m "feat: add atomic standalone relay persistence"
```

---

### Task 3: Native Node HTTP adapter with exact Relay V1 behavior

**Files:**
- Create: `standalone-relay/http.ts`
- Create: `tests/standalone-relay-http.test.ts`

**Interfaces:**
- Consumes: `RelayRuntime` from Task 2 and existing functions from `lib/quantic/relay.ts`.
- Produces: `export function createRelayRequestHandler(runtime: RelayRuntime): (request: IncomingMessage, response: ServerResponse) => Promise<void>`.
- Produces: `export const MAX_REQUEST_BYTES = 512 * 1024`.

- [ ] **Step 1: Write RED tests for health, CORS, routing, and error shape**

Build requests against a temporary native HTTP server using the handler. Verify:

```ts
assert.deepEqual(await health.json(), {
  ok: true,
  protocol: "quantic-relay/1",
  service: "Quantic Network Relay",
  time: /* ISO string */,
});
assert.equal(health.headers.get("access-control-allow-origin"), "*");
```

Verify `OPTIONS /api/quantic/send` returns 204 with:

- `Access-Control-Allow-Origin: *`
- `Access-Control-Allow-Methods: GET, POST, OPTIONS`
- `Access-Control-Allow-Headers: Content-Type, Authorization`

Verify unknown Quantic routes return 404 JSON and invalid methods return 405 JSON.

- [ ] **Step 2: Write RED compatibility tests for all V1 route mappings**

Tests should exercise the adapter mappings, not duplicate the cryptography engine:

- `POST /api/quantic/challenge` → `createIdentityChallenge`, status 201;
- `POST /api/quantic/register` → `registerIdentity`, status 201;
- `GET /api/quantic/resolve?handle=...` → `resolveIdentity`, status 200;
- `POST /api/quantic/devices/register` → `registerAuthorizedDevice`, status 201;
- `POST /api/quantic/send` → `enqueueEnvelope`, status 202;
- `GET /api/quantic/pull?handle=...&deviceId=...` → `{ envelopes }`;
- `POST /api/quantic/ack` → `acknowledgeEnvelopes`;
- `GET /api/quantic/receipts` → `{ receipts }`;
- `POST /api/quantic/receipts` → `acknowledgeReceipts`.

Use an invalid bearer token on authenticated routes and assert the existing engine's 401 message is returned as `{ error: error.message }`.

- [ ] **Step 3: Implement common HTTP helpers**

In `standalone-relay/http.ts`, add focused helpers:

```ts
function bearer(request: IncomingMessage): string | null;
function json(response: ServerResponse, status: number, payload: unknown): void;
async function readJsonBody(request: IncomingMessage): Promise<Record<string, unknown>>;
function applyCors(response: ServerResponse): void;
```

`readJsonBody` must count raw bytes and reject above `MAX_REQUEST_BYTES` with an internal typed HTTP error carrying status 413. Empty or malformed JSON returns status 400. Never include stack traces in the response.

- [ ] **Step 4: Implement route dispatch using runtime read/mutate boundaries**

Use `runtime.mutate()` for:

- challenge;
- register;
- devices/register;
- send;
- ack;
- receipts POST.

Use `runtime.read()` for:

- resolve;
- pull;
- receipts GET.

Health does not require the relay state.

Match the existing route body coercions exactly, including `String(body.foo ?? "")`, optional string device IDs, bearer extraction, and array checks for acknowledgement IDs.

- [ ] **Step 5: Map errors deterministically**

Error mapping:

```ts
if (error instanceof RelayError) json(res, error.status, { error: error.message });
else if (error instanceof RelayHttpRequestError) json(res, error.status, { error: error.message });
else json(res, 500, { error: "Erreur interne Quantic Relay." });
```

Malformed user JSON is 400, oversized bodies are 413, unsupported methods 405, unknown `/api/quantic/*` routes 404.

- [ ] **Step 6: Run HTTP tests and full suite**

```bash
node --experimental-strip-types --test tests/standalone-relay-http.test.ts
npm test
```

Expected: PASS.

- [ ] **Step 7: Commit Task 3**

```bash
git add standalone-relay/http.ts tests/standalone-relay-http.test.ts
git commit -m "feat: add standalone relay HTTP protocol adapter"
```

---

### Task 4: Standalone server lifecycle, configuration, and CLI entry point

**Files:**
- Create: `standalone-relay/server.ts`
- Create: `standalone-relay/main.ts`
- Create: `tests/standalone-relay-server.test.ts`
- Modify: `package.json`

**Interfaces:**
- Consumes: file store, runtime, and request handler from Tasks 2-3.
- Produces: `export type RelayServerOptions = { host?: string; port?: number; dataDir?: string }`.
- Produces: `export async function startRelayServer(options?: RelayServerOptions): Promise<RunningRelayServer>`.
- `RunningRelayServer` exposes `host`, actual numeric `port`, `url`, and `close(): Promise<void>`.

- [ ] **Step 1: Write RED lifecycle tests**

Use `port: 0` in tests and verify the OS-assigned port:

```ts
const relay = await startRelayServer({
  host: "127.0.0.1",
  port: 0,
  dataDir,
});
try {
  const response = await fetch(`${relay.url}/api/quantic/health`);
  assert.equal(response.status, 200);
} finally {
  await relay.close();
}
```

Verify `close()` flushes a final valid state file and closes the HTTP listener.

- [ ] **Step 2: Implement `startRelayServer()`**

Sequence:

1. resolve defaults `127.0.0.1`, `8787`, `./data`;
2. create file store;
3. create runtime;
4. `await runtime.initialize()` before binding any socket;
5. create `http.createServer()` with the async handler and an error guard;
6. listen;
7. return actual bound address and `close()`.

`close()` must first stop accepting connections with `server.close()`, wait for in-flight requests to finish, then `await runtime.flush()`.

- [ ] **Step 3: Implement CLI/environment parsing**

`standalone-relay/main.ts` reads:

```ts
const host = process.env.QUANTIC_RELAY_HOST ?? "127.0.0.1";
const port = parsePort(process.env.QUANTIC_RELAY_PORT ?? "8787");
const dataDir = process.env.QUANTIC_RELAY_DATA_DIR ?? "./data";
```

Reject a non-integer port outside `1..65535` in CLI mode. Start the server and print one concise line containing the listening URL and data directory.

Register `SIGINT` and `SIGTERM` exactly once. The first signal begins graceful shutdown; subsequent signal handling must not start a second flush concurrently.

- [ ] **Step 4: Add package scripts**

Update `package.json`:

```json
{
  "scripts": {
    "relay:start": "node --experimental-strip-types standalone-relay/main.ts",
    "relay:dev": "node --watch --experimental-strip-types standalone-relay/main.ts"
  }
}
```

Keep the existing scripts unchanged otherwise.

- [ ] **Step 5: Run server tests and smoke-start the CLI**

```bash
node --experimental-strip-types --test tests/standalone-relay-server.test.ts
QUANTIC_RELAY_PORT=8787 QUANTIC_RELAY_DATA_DIR=.tmp-relay node --experimental-strip-types standalone-relay/main.ts
```

In the smoke run, request `/api/quantic/health`, terminate the process, and verify `.tmp-relay/relay-state.json` is valid JSON. Remove `.tmp-relay` afterward.

- [ ] **Step 6: Run full tests**

```bash
npm test
```

Expected: PASS.

- [ ] **Step 7: Commit Task 4**

```bash
git add standalone-relay/server.ts standalone-relay/main.ts tests/standalone-relay-server.test.ts package.json
git commit -m "feat: add standalone Quantic Relay server"
```

---

### Task 5: End-to-end restart/recovery proof

**Files:**
- Create: `tests/standalone-relay-restart.test.ts`

**Interfaces:**
- Consumes: public HTTP Relay V1 protocol and `startRelayServer()` only.
- Produces: executable proof that encrypted queue and receipts survive complete server destruction/recreation on the same data directory.

- [ ] **Step 1: Add crypto helpers inside the integration test**

Use `node:crypto` so the test performs a real ownership proof:

```ts
const encryption = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
const signing = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
const publicKey = encryption.publicKey.export({ format: "jwk" });
const signingPublicKey = signing.publicKey.export({ format: "jwk" });
```

After `POST /challenge`, sign the returned challenge with:

```ts
const signature = sign(
  "sha256",
  Buffer.from(challenge, "utf8"),
  { key: signing.privateKey, dsaEncoding: "ieee-p1363" },
).toString("base64");
```

Use deterministic-looking auth tokens of at least 40 characters generated per test, but never hard-code real secrets.

- [ ] **Step 2: Register Alice and Bob over HTTP**

For each user:

1. generate encryption/signing key pairs;
2. `POST /api/quantic/challenge`;
3. sign challenge;
4. `POST /api/quantic/register`;
5. retain `canonicalAddress` and `rootDeviceId` from the HTTP response.

Do not import `registerIdentity()` directly in this test.

- [ ] **Step 3: Send an encrypted envelope and destroy process-equivalent server state**

Send from Alice to Bob using `POST /api/quantic/send` with:

```ts
{
  clientMessageId: "msg-restart-0001",
  from: alice.canonicalAddress,
  fromDeviceId: alice.rootDeviceId,
  to: bob.canonicalAddress,
  toDeviceId: bob.rootDeviceId,
  ciphertext: "opaque-test-ciphertext",
  iv: "opaque-test-iv",
  ephemeralPublicKey: alice.publicKey
}
```

Authorization is `Bearer ${alice.authToken}`. Assert HTTP 202, then call `relay.close()` and discard that `RunningRelayServer` instance entirely.

- [ ] **Step 4: Restart on the same directory and prove Bob receives the queue**

Create a new server instance using the same `dataDir`. Call Bob's `GET /api/quantic/pull` with bearer token and device ID. Assert exactly one envelope with `clientMessageId === "msg-restart-0001"`.

- [ ] **Step 5: Acknowledge, restart again, and prove queue deletion plus durable receipt**

POST Bob's envelope ID to `/api/quantic/ack`, close the second server, create a third server, then assert:

- Bob's pull returns `envelopes: []`;
- Alice's receipts GET contains one receipt for `msg-restart-0001`.

- [ ] **Step 6: Acknowledge the receipt and prove the final deletion also survives restart**

POST the receipt ID to `/api/quantic/receipts`, close the third server, start a fourth server on the same directory, and assert Alice's receipts array is empty.

- [ ] **Step 7: Run the restart test repeatedly**

```bash
for i in 1 2 3; do node --experimental-strip-types --test tests/standalone-relay-restart.test.ts || exit 1; done
npm test
```

Expected: all iterations PASS without port collisions or leaked handles.

- [ ] **Step 8: Commit Task 5**

```bash
git add tests/standalone-relay-restart.test.ts
git commit -m "test: prove Quantic Relay survives restarts"
```

---

### Task 6: Self-hosting documentation and final verification

**Files:**
- Create: `docs/quantic-relay-standalone.md`
- Modify: `docs/quantic-relay-v1.md`

**Interfaces:**
- Documents the scripts and configuration produced in Task 4.
- Does not alter protocol behavior.

- [ ] **Step 1: Write the standalone relay operator guide**

Document exact local commands:

```bash
npm install
npm run relay:start
```

Document configuration:

```bash
QUANTIC_RELAY_HOST=0.0.0.0 \
QUANTIC_RELAY_PORT=8787 \
QUANTIC_RELAY_DATA_DIR=/var/lib/quantic-relay \
npm run relay:start
```

State explicitly:

- default mode is loopback-only;
- `relay-state.json` contains public identity metadata and encrypted transport data, so its directory still requires OS access control and backups;
- Internet publication requires TLS/HTTPS through a reverse proxy;
- the client adds the endpoint from QuanticMail `/network`;
- a standalone relay does not make direct P2P or cross-relay replication available yet.

- [ ] **Step 2: Update Relay Protocol V1 documentation**

Replace the statement that a full QuanticMail instance is the current self-hosting model with two supported implementations:

1. QuanticMail's built-in Next.js routes;
2. the standalone native Node relay.

Keep the protocol limitations section unchanged except that in-memory-only persistence is no longer true for the standalone implementation.

- [ ] **Step 3: Run all verification commands**

```bash
npm install
npm test
npm run build
npm run lint
```

Expected: all exit 0 under Node.js 22.

- [ ] **Step 4: Validate no private material is written by the persistence code**

Search the standalone persistence and snapshot files:

```bash
grep -RniE 'privateKey|signingPrivate|vaultPassword|plaintext|messageBody' standalone-relay lib/quantic/relay.ts
```

Review every match. Expected: no persistence field or write path serializes private keys, vault passwords, or plaintext message content.

- [ ] **Step 5: Commit docs**

```bash
git add docs/quantic-relay-standalone.md docs/quantic-relay-v1.md
git commit -m "docs: document standalone Quantic Relay"
```

- [ ] **Step 6: Inspect branch diff against the multi-relay base**

```bash
git diff --check feat/quantic-network-v1-multirelay...HEAD
git diff --stat feat/quantic-network-v1-multirelay...HEAD
```

Expected: no whitespace errors; changes are limited to spec/plan docs, relay persistence, standalone server, tests, package scripts, and relay docs.

- [ ] **Step 7: Open a stacked pull request**

Open the PR with:

- base: `feat/quantic-network-v1-multirelay`
- head: `feat/quantic-relay-standalone`
- title: `Quantic Network V1 — standalone durable relay`

PR body must state that it depends on PR #13 and list the restart/recovery acceptance test. After PR #13 merges, retarget this PR to `main` and re-run CI before merge.
