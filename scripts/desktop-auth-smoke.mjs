// End-to-end integration test against the *packaged* local Windows relay.
// Uses throwaway keys/data and a loopback-only test instance. Never reads a
// user's vault, message history or production relay.
import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, randomBytes, randomUUID, sign } from "node:crypto";

const digest = (key) => createHash("sha256").update(`P-256:${key.x}:${key.y}`).digest("hex");

async function json(url, { method = "GET", token, body } = {}) {
  const response = await fetch(url, {
    method,
    headers: {
      ...(body === undefined ? {} : { "content-type": "application/json" }),
      ...(token ? { authorization: `Bearer ${token}` } : {}),
    },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    signal: AbortSignal.timeout(10_000),
  });
  return { response, result: await response.json().catch(() => ({})) };
}

export async function smokeDeviceAuthentication(apiOrigin) {
  const signing = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const encryption = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const ephemeral = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const signingPublicKey = signing.publicKey.export({ format: "jwk" });
  const publicKey = encryption.publicKey.export({ format: "jwk" });
  const ephemeralPublicKey = ephemeral.publicKey.export({ format: "jwk" });
  const canonicalAddress = `desktopauth~${digest(signingPublicKey).slice(0, 32)}@quantic`;
  const oldDeviceId = `d-${digest(publicKey).slice(0, 10)}`;
  const deviceId = `d-${digest(publicKey).slice(0, 32)}`;
  const authToken = randomBytes(32).toString("base64");

  const challenge = await json(`${apiOrigin}/api/quantic/challenge`, {
    method: "POST",
    body: { handle: canonicalAddress, publicKey, signingPublicKey },
  });
  assert.equal(challenge.response.status, 201,
    `Challenge root impossible: ${JSON.stringify(challenge.result)}`);
  const signature = sign("sha256", Buffer.from(challenge.result.challenge), {
    key: signing.privateKey, dsaEncoding: "ieee-p1363"
  }).toString("base64");
  const basic = { handle: canonicalAddress, publicKey, signingPublicKey, authToken };

  // Simulate existing Windows 1.3.5 registration that omitted the device ID.
  const previous = await json(`${apiOrigin}/api/quantic/register`, {
    method: "POST", body: { ...basic, challenge: challenge.result.challenge, signature },
  });
  assert.equal(previous.response.status, 201,
    `Ancien enregistrement impossible: ${JSON.stringify(previous.result)}`);
  assert.equal(previous.result.rootDeviceId, oldDeviceId);

  const envelope = {
    clientMessageId: randomUUID(),
    from: canonicalAddress, fromDeviceId: deviceId,
    to: canonicalAddress, toDeviceId: deviceId,
    ciphertext: "AQIDBAUGBwgJ", iv: "AAAAAAAAAAAAAAAA",
    ephemeralPublicKey,
  };
  const denied = await json(`${apiOrigin}/api/quantic/send`, {
    method: "POST", token: authToken, body: envelope,
  });
  assert.equal(denied.response.status, 401,
    "Avant migration, le relais doit refuser le mauvais identifiant d'appareil.");

  // New client sends the full 32-hex ID; signed challenge is not necessary
  // again because the local device token is already authenticated.
  const repaired = await json(`${apiOrigin}/api/quantic/register`, {
    method: "POST", body: { ...basic, deviceId },
  });
  assert.equal(repaired.response.status, 201,
    `Migration du relais impossible: ${JSON.stringify(repaired.result)}`);
  assert.equal(repaired.result.rootDeviceId, deviceId);

  const queued = await json(`${apiOrigin}/api/quantic/send`, {
    method: "POST", token: authToken, body: envelope,
  });
  assert.equal(queued.response.status, 202,
    `Authentification root 32 caractères toujours refusée: ${JSON.stringify(queued.result)}`);
  const pulled = await json(
    `${apiOrigin}/api/quantic/pull?handle=${encodeURIComponent(canonicalAddress)}&deviceId=${encodeURIComponent(deviceId)}`,
    { token: authToken }
  );
  assert.equal(pulled.response.status, 200,
    `Lecture après migration refusée: ${JSON.stringify(pulled.result)}`);
  assert.equal(pulled.result.envelopes?.length, 1);
  assert.equal(pulled.result.envelopes?.[0]?.clientMessageId, envelope.clientMessageId);
  console.log("OK : 401 de l'ancien identifiant reproduit, migration 10→32, envoi 202 et lecture 200 vérifiés.");
}
