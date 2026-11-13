import test from "node:test";
import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign, webcrypto } from "node:crypto";
import { readFileSync } from "node:fs";
import {
  VAULT_BRIDGE_URL, VAULT_AUDIENCE,
  readVaultStatus, validateVaultStatus, verifyVaultProof,
} from "../lib/quantic/vault-bridge.mjs";

function b64url(bytes) { return Buffer.from(bytes).toString("base64url"); }

function createProof(algorithm = "ed25519", overrides = {}) {
  const isP256 = algorithm === "ecdsa-p256-sha256";
  const { publicKey, privateKey } = generateKeyPairSync(isP256 ? "ec" : "ed25519", isP256 ? { namedCurve: "prime256v1" } : {});
  const der = publicKey.export({ type: "spki", format: "der" });
  const keyId = "qid_" + createHash("sha256").update(der).digest("hex").slice(0, 32);
  const challenge = b64url(webcrypto.getRandomValues(new Uint8Array(32)));
  const status = validateVaultStatus({
    version: 1, product: "Quantic Identity Vault",
    identityAvailable: true, keyId, publicKey: b64url(der),
    algorithm, label: "Compte local de test"
  });
  const payload = JSON.stringify({
    version: 1, keyId, challenge, audience: VAULT_AUDIENCE, issuedAt: new Date().toISOString(),
    ...overrides,
  });
  const signature = b64url(sign(isP256 ? "sha256" : null, Buffer.from(payload),
    isP256 ? { key: privateKey, dsaEncoding: "ieee-p1363" } : privateKey));
  return { status, challenge, proof: { version: 1, algorithm, keyId, publicKey: status.publicKey, payload, signature } };
}

test("Quantic Identity Vault localhost bridge is the actual unlocked-ID source", async () => {
  const data = await readVaultStatus(async (url, init) => {
    assert.equal(url, VAULT_BRIDGE_URL + "/v1/status");
    assert.equal(init.method, "GET");
    return { ok: true, json: async () => ({
      version: 1, product: "Quantic Identity Vault",
      identityAvailable: false, keyId: null, publicKey: null
    }) };
  });
  assert.equal(data.available, false);
});

test("Quantic ID status accepts bridge protocol v1/v3 and rejects spoofed products", () => {
  assert.equal(validateVaultStatus({ version: 3, product: "Quantic Identity Vault", identityAvailable: false }).available, false);
  assert.throws(() => validateVaultStatus({ version: 1, product: "Something else", identityAvailable: true }), /non reconnue/);
});

test("Quantic ID local Ed25519 proof is independently verified", async () => {
  const { status, proof, challenge } = createProof("ed25519");
  const answer = await verifyVaultProof(status, proof, challenge, webcrypto);
  assert.equal(answer.keyId, status.keyId);
});

test("Quantic Hardware Key P-256 proof verifies without exporting private key", async () => {
  const { status, proof, challenge } = createProof("ecdsa-p256-sha256");
  const answer = await verifyVaultProof(status, proof, challenge, webcrypto);
  assert.equal(answer.keyId, status.keyId);
});

test("a signed assertion for the wrong audience is rejected", async () => {
  const { status, proof, challenge } = createProof("ed25519", { audience: "evil-origin" });
  await assert.rejects(verifyVaultProof(status, proof, challenge, webcrypto), /ne vise pas cette application/);
});

test("an expired or replayed proof cannot authenticate another challenge", async () => {
  const { status, proof, challenge } = createProof("ed25519", { issuedAt: "2020-01-01T00:00:00.000Z" });
  await assert.rejects(verifyVaultProof(status, proof, challenge, webcrypto), /expirée/);
  const fresh = createProof("ed25519");
  await assert.rejects(verifyVaultProof(fresh.status, fresh.proof, challenge, webcrypto), /expirée/);
});

test("a forged signature is rejected cryptographically", async () => {
  const { status, proof, challenge } = createProof("ed25519");
  const forged = { ...proof, signature: b64url(Buffer.alloc(64)) };
  await assert.rejects(verifyVaultProof(status, forged, challenge, webcrypto), /signature Quantic ID/);
});

test("desktop mailbox gate uses Quantic ID proof but does not mistake QID for mail private keys", () => {
  const layout = readFileSync(new URL("../app/layout.tsx", import.meta.url), "utf8");
  const gate = readFileSync(new URL("../components/quantic-id-desktop-gate.tsx", import.meta.url), "utf8");
  assert.match(layout, /QuanticIdDesktopGate/);
  assert.match(gate, /verifyUnlockedVault/);
  assert.match(gate, /Identity Vault/);
  assert.doesNotMatch(gate, /signingPrivateKey|authToken:/);
});
