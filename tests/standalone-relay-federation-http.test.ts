import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import * as fs from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  canonicalPortableEnvelopeText,
  canonicalRouteManifestText,
} from "../lib/quantic/federation-core.mjs";
import { canonicalManifestText } from "../lib/quantic/manifest-core.mjs";
import { federationForwardNonce } from "../standalone-relay/federation-client.ts";
import { verifyRelayHello } from "../standalone-relay/identity.ts";
import { startRelayServer } from "../standalone-relay/server.ts";

async function tempDir() {
  return fs.mkdtemp(join(tmpdir(), "quantic-relay-federation-http-"));
}

function keys() {
  return generateKeyPairSync("ec", { namedCurve: "prime256v1" });
}

function publicJwk(pair: ReturnType<typeof keys>) {
  return pair.publicKey.export({ format: "jwk" });
}

function fingerprint(key: JsonWebKey, length = 32) {
  return createHash("sha256").update(`P-256:${key.x}:${key.y}`).digest("hex").slice(0, length);
}

function deviceId(key: JsonWebKey) {
  return `d-${fingerprint(key, 10)}`;
}

function signedIdentity(handle: string) {
  const owner = keys();
  const encryption = keys();
  const ownerPublic = publicJwk(owner);
  const encryptionPublic = publicJwk(encryption);
  const fp = fingerprint(ownerPublic, 32);
  const canonicalAddress = `${handle}~${fp}@quantic`;
  const payload = {
    version: 1 as const,
    sequence: 1,
    canonicalAddress,
    handle,
    fingerprint: fp,
    identityPublicKey: encryptionPublic,
    identitySigningPublicKey: ownerPublic,
    devices: [{
      deviceId: deviceId(encryptionPublic),
      label: `${handle} root`,
      publicKey: encryptionPublic,
      deviceSigningPublicKey: ownerPublic,
      kind: "root" as const,
      issuedAt: new Date(Date.now() - 60_000).toISOString(),
    }],
    revocations: [],
    issuedAt: new Date(Date.now() - 60_000).toISOString(),
  };
  const signature = sign("sha256", Buffer.from(canonicalManifestText(payload), "utf8"), {
    key: owner.privateKey,
    dsaEncoding: "ieee-p1363",
  }).toString("base64");
  return {
    owner,
    encryption,
    deviceId: deviceId(encryptionPublic),
    canonicalAddress,
    manifest: { format: "quantic-identity-manifest" as const, version: 1 as const, payload, signature },
  };
}

async function registerIdentityOnRelay(
  relayUrl: string,
  identity: ReturnType<typeof signedIdentity>,
  authToken: string,
) {
  const challengeResponse = await fetch(`${relayUrl}/api/quantic/challenge`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      handle: identity.canonicalAddress,
      publicKey: identity.manifest.payload.identityPublicKey,
      signingPublicKey: identity.manifest.payload.identitySigningPublicKey,
    }),
  });
  assert.equal(challengeResponse.status, 201);
  const challenge = await challengeResponse.json() as { challenge: string };
  const ownershipSignature = sign("sha256", Buffer.from(challenge.challenge, "utf8"), {
    key: identity.owner.privateKey,
    dsaEncoding: "ieee-p1363",
  }).toString("base64");
  const registerResponse = await fetch(`${relayUrl}/api/quantic/register`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      handle: identity.canonicalAddress,
      publicKey: identity.manifest.payload.identityPublicKey,
      signingPublicKey: identity.manifest.payload.identitySigningPublicKey,
      authToken,
      challenge: challenge.challenge,
      signature: ownershipSignature,
    }),
  });
  assert.equal(registerResponse.status, 201);
}

async function relayHello(relayUrl: string, relayId: string, nonce = `nonce-${"a".repeat(24)}`) {
  const response = await fetch(`${relayUrl}/api/quantic/federation/hello`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ nonce }),
  });
  assert.equal(response.status, 200);
  return verifyRelayHello(await response.json(), nonce, relayId);
}

function signedRoute(
  recipient: ReturnType<typeof signedIdentity>,
  relay: Awaited<ReturnType<typeof relayHello>>,
) {
  const payload = {
    version: 1 as const,
    sequence: 1,
    canonicalAddress: recipient.canonicalAddress,
    identitySigningPublicKey: recipient.manifest.payload.identitySigningPublicKey,
    identityManifestSequence: recipient.manifest.payload.sequence,
    cryptoProfileSequence: null,
    cryptoProfileDigest: null,
    relays: [{
      relayId: relay.relayId,
      endpoint: relay.endpoint,
      priority: 10,
      protocols: ["quantic-federation/1"],
      classicalSigningPublicKey: relay.classicalSigningPublicKey,
      expiresAt: new Date(Date.now() + 24 * 60 * 60_000).toISOString(),
    }],
    issuedAt: new Date(Date.now() - 60_000).toISOString(),
    expiresAt: new Date(Date.now() + 24 * 60 * 60_000).toISOString(),
  };
  const p256 = sign("sha256", Buffer.from(canonicalRouteManifestText(payload), "utf8"), {
    key: recipient.owner.privateKey,
    dsaEncoding: "ieee-p1363",
  }).toString("base64");
  return { format: "quantic-route-manifest" as const, version: 1 as const, payload, signatures: { p256 } };
}

function signedEnvelope(
  sender: ReturnType<typeof signedIdentity>,
  recipient: ReturnType<typeof signedIdentity>,
) {
  const ephemeral = keys();
  const envelope = {
    format: "quantic-envelope" as const,
    version: 2 as const,
    clientMessageId: "msg-federation-http-0001",
    from: sender.canonicalAddress,
    fromDeviceId: sender.deviceId,
    to: recipient.canonicalAddress,
    toDeviceId: recipient.deviceId,
    keyMode: "v1-static-fallback" as const,
    cryptoSuite: "QNT-P256-AES256GCM-1",
    classicalEphemeralPublicKey: publicJwk(ephemeral),
    iv: "aXYtbm9uY2U=",
    ciphertext: "ZmVkZXJhdGVkLWNpcGhlcnRleHQ=",
    createdAt: new Date(Date.now() - 30_000).toISOString(),
    expiresAt: new Date(Date.now() + 10 * 60_000).toISOString(),
    signatures: { p256Device: "placeholder" },
  };
  envelope.signatures.p256Device = sign(
    "sha256",
    Buffer.from(canonicalPortableEnvelopeText(envelope), "utf8"),
    { key: sender.owner.privateKey, dsaEncoding: "ieee-p1363" },
  ).toString("base64");
  return envelope;
}

test("standalone relay exposes a signed nonce-bound federation hello", async () => {
  const dataDir = await tempDir();
  const relay = await startRelayServer({ host: "127.0.0.1", port: 0, dataDir });
  try {
    const nonce = "nonce-0123456789abcdef";
    const response = await fetch(`${relay.url}/api/quantic/federation/hello`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ nonce }),
    });
    assert.equal(response.status, 200);
    const hello = await response.json();
    const verified = verifyRelayHello(hello, nonce, relay.relayId);
    assert.equal(verified.relayId, relay.relayId);
    assert.equal(verified.endpoint, relay.url);
    assert.ok(verified.protocols.includes("quantic-federation/1"));
  } finally {
    await relay.close();
    await fs.rm(dataDir, { recursive: true, force: true });
  }
});

test("federation hello rejects a weak nonce", async () => {
  const dataDir = await tempDir();
  const relay = await startRelayServer({ host: "127.0.0.1", port: 0, dataDir });
  try {
    const response = await fetch(`${relay.url}/api/quantic/federation/hello`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ nonce: "tiny" }),
    });
    assert.equal(response.status, 400);
  } finally {
    await relay.close();
    await fs.rm(dataDir, { recursive: true, force: true });
  }
});

test("destination relay accepts a sender-signed federation envelope without the sender auth token", async () => {
  const originDataDir = await tempDir();
  const destinationDataDir = await tempDir();
  const originRelay = await startRelayServer({ host: "127.0.0.1", port: 0, dataDir: originDataDir });
  const destinationRelay = await startRelayServer({ host: "127.0.0.1", port: 0, dataDir: destinationDataDir });
  const bob = signedIdentity("bob");
  const alice = signedIdentity("alice");
  const bobToken = "bob-local-device-auth-token-000000000000000000000001";
  const federationId = "fed-http-0000000000000001";
  try {
    await registerIdentityOnRelay(destinationRelay.url, bob, bobToken);
    const destinationHello = await relayHello(destinationRelay.url, destinationRelay.relayId);
    const route = signedRoute(bob, destinationHello);
    const envelope = signedEnvelope(alice, bob);
    const originHello = await relayHello(
      originRelay.url,
      originRelay.relayId,
      federationForwardNonce(federationId),
    );

    const response = await fetch(`${destinationRelay.url}/api/quantic/federation/forward`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        format: "quantic-federation-forward",
        version: 1,
        federationId,
        originRelay: originHello,
        previousRelayId: originRelay.relayId,
        hopLimit: 4,
        visitedRelayIds: [originRelay.relayId],
        expiresAt: new Date(Date.now() + 10 * 60_000).toISOString(),
        senderIdentityManifest: alice.manifest,
        recipientIdentityManifest: bob.manifest,
        recipientRouteManifest: route,
        envelope,
        previousRelayAttestation: originHello.p256Signature,
      }),
    });
    assert.equal(response.status, 202);
    const forwarded = await response.json() as { duplicate: boolean };
    assert.equal(forwarded.duplicate, false);

    const pull = await fetch(
      `${destinationRelay.url}/api/quantic/pull?handle=${encodeURIComponent(bob.canonicalAddress)}&deviceId=${encodeURIComponent(bob.deviceId)}`,
      { headers: { authorization: `Bearer ${bobToken}` } },
    );
    assert.equal(pull.status, 200);
    const body = await pull.json() as { envelopes: Array<{ clientMessageId: string; ciphertext: string }> };
    assert.equal(body.envelopes.length, 1);
    assert.equal(body.envelopes[0].clientMessageId, envelope.clientMessageId);
    assert.equal(body.envelopes[0].ciphertext, envelope.ciphertext);
  } finally {
    await originRelay.close();
    await destinationRelay.close();
    await fs.rm(originDataDir, { recursive: true, force: true });
    await fs.rm(destinationDataDir, { recursive: true, force: true });
  }
});

test("destination relay rejects a valid route that does not authorize itself", async () => {
  const originDataDir = await tempDir();
  const destinationDataDir = await tempDir();
  const originRelay = await startRelayServer({ host: "127.0.0.1", port: 0, dataDir: originDataDir });
  const destinationRelay = await startRelayServer({ host: "127.0.0.1", port: 0, dataDir: destinationDataDir });
  const bob = signedIdentity("bobby");
  const alice = signedIdentity("alicia");
  const bobToken = "bob-route-local-auth-token-000000000000000000000001";
  const federationId = "fed-http-0000000000000002";
  try {
    await registerIdentityOnRelay(destinationRelay.url, bob, bobToken);
    const originHello = await relayHello(
      originRelay.url,
      originRelay.relayId,
      federationForwardNonce(federationId),
    );
    const route = signedRoute(bob, originHello);
    const envelope = signedEnvelope(alice, bob);
    const response = await fetch(`${destinationRelay.url}/api/quantic/federation/forward`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        format: "quantic-federation-forward",
        version: 1,
        federationId,
        originRelay: originHello,
        previousRelayId: originRelay.relayId,
        hopLimit: 4,
        visitedRelayIds: [originRelay.relayId],
        expiresAt: new Date(Date.now() + 10 * 60_000).toISOString(),
        senderIdentityManifest: alice.manifest,
        recipientIdentityManifest: bob.manifest,
        recipientRouteManifest: route,
        envelope,
        previousRelayAttestation: originHello.p256Signature,
      }),
    });
    const body = await response.json() as { error: string };
    assert.equal(response.status, 403, body.error);
    assert.match(body.error, /pas autorisé/i);
  } finally {
    await originRelay.close();
    await destinationRelay.close();
    await fs.rm(originDataDir, { recursive: true, force: true });
    await fs.rm(destinationDataDir, { recursive: true, force: true });
  }
});

test("durable standalone relay denies revoked linked device on send, pull, ack and receipts across restart",async()=>{
 const dataDir=await tempDir();
 let relay=await startRelayServer({host:"127.0.0.1",port:0,dataDir});
 const alice=signedIdentity("alice"),bob=signedIdentity("bob");
 const aliceToken="root-token-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
 const bobToken="root-token-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
 const linkedToken="linked-token-cccccccccccccccccccccccccccccccccccccc";
 const linkedEnc=keys(),linkedSign=keys();
 const linkedEncJwk=publicJwk(linkedEnc),linkedSignJwk=publicJwk(linkedSign);
 const linkedId=deviceId(linkedEncJwk);
 const now=new Date().toISOString();
 function signedManifest(payload:typeof alice.manifest.payload){
  return {format:"quantic-identity-manifest",version:1,payload,signature:sign("sha256",
   Buffer.from(canonicalManifestText(payload),"utf8"),
   {key:alice.owner.privateKey,dsaEncoding:"ieee-p1363"}).toString("base64")};
 }
 function certificate(){
  const p=alice.manifest.payload;
  const payload={version:1,canonicalAddress:alice.canonicalAddress,handle:p.handle,
   fingerprint:p.fingerprint,identityPublicKey:p.identityPublicKey,
   identitySigningPublicKey:p.identitySigningPublicKey,
   deviceId:linkedId,deviceLabel:"linked test device",
   devicePublicKey:linkedEncJwk,deviceSigningPublicKey:linkedSignJwk,issuedAt:now};
  const message=["quantic-device-certificate-v1",payload.canonicalAddress,payload.handle,payload.fingerprint,
   "P-256:"+payload.identityPublicKey.x+":"+payload.identityPublicKey.y,
   "P-256:"+payload.identitySigningPublicKey.x+":"+payload.identitySigningPublicKey.y,
   payload.deviceId,payload.deviceLabel,
   "P-256:"+payload.devicePublicKey.x+":"+payload.devicePublicKey.y,
   "P-256:"+payload.deviceSigningPublicKey.x+":"+payload.deviceSigningPublicKey.y,
   payload.issuedAt].join("\n");
  return {format:"quantic-device-certificate",version:1,payload,
   signature:sign("sha256",Buffer.from(message),{key:alice.owner.privateKey,
    dsaEncoding:"ieee-p1363"}).toString("base64")};
 }
 const body=(value:unknown)=>({method:"POST",headers:{"content-type":"application/json"},
  body:JSON.stringify(value)});
 const authed=(token:string,value:unknown)=>({method:"POST",
  headers:{"content-type":"application/json",authorization:"Bearer "+token},
  body:JSON.stringify(value)});
 try{
  await registerIdentityOnRelay(relay.url,alice,aliceToken);
  await registerIdentityOnRelay(relay.url,bob,bobToken);
  const registered=await fetch(relay.url+"/api/quantic/devices/register",
   body({certificate:certificate(),authToken:linkedToken}));
  assert.equal(registered.status,201,await registered.text());
  const root=alice.manifest.payload;
  const linked={deviceId:linkedId,label:"linked test device",kind:"linked",
   publicKey:linkedEncJwk,deviceSigningPublicKey:linkedSignJwk,issuedAt:now};
  const active={...root,sequence:2,devices:[...root.devices,linked],issuedAt:now};
  const published=await fetch(relay.url+"/api/quantic/manifest",
   body({manifest:signedManifest(active)}));
  assert.equal(published.status,200,await published.text());
  const pullUrl=()=>relay.url+"/api/quantic/pull?handle="+encodeURIComponent(alice.canonicalAddress)+
   "&deviceId="+encodeURIComponent(linkedId);
  assert.equal((await fetch(pullUrl(),{headers:{authorization:"Bearer "+linkedToken}})).status,200);
  const revoked={...active,sequence:3,devices:root.devices,
   revocations:[{deviceId:linkedId,revokedAt:new Date(Date.now()+1000).toISOString(),reason:"lost"}],
   issuedAt:new Date(Date.now()+1000).toISOString()};
  const revocation=await fetch(relay.url+"/api/quantic/manifest",
   body({manifest:signedManifest(revoked)}));
  assert.equal(revocation.status,200,await revocation.text());
  async function checkDenied(){
   assert.equal((await fetch(pullUrl(),{headers:{authorization:"Bearer "+linkedToken}})).status,401);
   assert.equal((await fetch(relay.url+"/api/quantic/ack",
    authed(linkedToken,{handle:alice.canonicalAddress,deviceId:linkedId,ids:[]}))).status,401);
   assert.equal((await fetch(relay.url+"/api/quantic/receipts?handle="+
    encodeURIComponent(alice.canonicalAddress)+"&deviceId="+linkedId,
    {headers:{authorization:"Bearer "+linkedToken}})).status,401);
   assert.equal((await fetch(relay.url+"/api/quantic/receipts",
    authed(linkedToken,{handle:alice.canonicalAddress,deviceId:linkedId,ids:[]}))).status,401);
   const wire={from:alice.canonicalAddress,fromDeviceId:linkedId,to:bob.canonicalAddress,
    toDeviceId:bob.deviceId,clientMessageId:"message-denied-00000001",
    ciphertext:"c2VjcmV0",iv:"YWJjZGVmZ2hpamts",
    ephemeralPublicKey:publicJwk(keys())};
   assert.equal((await fetch(relay.url+"/api/quantic/send",authed(linkedToken,wire))).status,401);
   assert.equal((await fetch(relay.url+"/api/quantic/send",authed(bobToken,{
    ...wire,from:bob.canonicalAddress,fromDeviceId:bob.deviceId,
    to:alice.canonicalAddress,toDeviceId:linkedId}))).status,401);
  }
  await checkDenied();
  await relay.close();
  relay=await startRelayServer({host:"127.0.0.1",port:0,dataDir});
  await checkDenied();
 }finally{
  await relay.close();
  await fs.rm(dataDir,{recursive:true,force:true});
 }
});
