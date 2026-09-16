import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign,
  verify,
} from "node:crypto";
import * as fs from "node:fs/promises";
import { join } from "node:path";

export type RelayIdentity = {
  relayId: string;
  publicKeyJwk: JsonWebKey;
  privateKeyPem: string;
};

export type SignedRelayHello = {
  format: "quantic-relay-hello";
  version: 1;
  relayId: string;
  endpoint: string;
  protocols: string[];
  capabilities: string[];
  nonce: string;
  issuedAt: string;
  classicalSigningPublicKey: JsonWebKey;
  p256Signature: string;
};

type StoredRelayIdentity = RelayIdentity & {
  format: "quantic-relay-identity";
  version: 1;
};

const RELAY_ID = /^[0-9a-f]{64}$/;
const NONCE = /^[A-Za-z0-9._~-]{16,256}$/;
const MAX_HELLO_AGE_MS = 5 * 60 * 1000;

function assertP256PublicKey(key: JsonWebKey) {
  if (key.kty !== "EC" || key.crv !== "P-256" || !key.x || !key.y) {
    throw new Error("Clé publique du relais invalide.");
  }
}

function orderedPublicKey(key: JsonWebKey) {
  assertP256PublicKey(key);
  return { kty: "EC", crv: "P-256", x: key.x, y: key.y };
}

function normalizeEndpoint(value: string) {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error("Endpoint du relais invalide.");
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") {
    throw new Error("Endpoint du relais invalide.");
  }
  if (url.username || url.password || url.search || url.hash) {
    throw new Error("Endpoint du relais non canonique.");
  }
  return url.origin;
}

export function relayIdForPublicKey(publicKeyJwk: JsonWebKey) {
  assertP256PublicKey(publicKeyJwk);
  const spki = createPublicKey({ key: publicKeyJwk, format: "jwk" }).export({
    type: "spki",
    format: "der",
  });
  return createHash("sha256").update(spki).digest("hex");
}

function canonicalHelloText(hello: Omit<SignedRelayHello, "p256Signature">) {
  return JSON.stringify({
    format: hello.format,
    version: hello.version,
    relayId: hello.relayId,
    endpoint: normalizeEndpoint(hello.endpoint),
    protocols: [...hello.protocols].sort(),
    capabilities: [...hello.capabilities].sort(),
    nonce: hello.nonce,
    issuedAt: hello.issuedAt,
    classicalSigningPublicKey: orderedPublicKey(hello.classicalSigningPublicKey),
  });
}

function validateStoredIdentity(value: unknown): StoredRelayIdentity {
  const stored = value as Partial<StoredRelayIdentity> | null;
  if (!stored || stored.format !== "quantic-relay-identity" || stored.version !== 1) {
    throw new Error("Identité persistante Quantic Relay invalide.");
  }
  if (!stored.publicKeyJwk || typeof stored.privateKeyPem !== "string") {
    throw new Error("Clés persistantes Quantic Relay invalides.");
  }
  assertP256PublicKey(stored.publicKeyJwk);
  const calculatedRelayId = relayIdForPublicKey(stored.publicKeyJwk);
  if (stored.relayId !== calculatedRelayId || !RELAY_ID.test(stored.relayId)) {
    throw new Error("Relay ID persistant incohérent.");
  }
  const privatePublic = createPublicKey(createPrivateKey(stored.privateKeyPem)).export({ format: "jwk" }) as JsonWebKey;
  if (
    privatePublic.kty !== stored.publicKeyJwk.kty ||
    privatePublic.crv !== stored.publicKeyJwk.crv ||
    privatePublic.x !== stored.publicKeyJwk.x ||
    privatePublic.y !== stored.publicKeyJwk.y
  ) {
    throw new Error("La clé privée persistante ne correspond pas au Relay ID.");
  }
  return stored as StoredRelayIdentity;
}

async function readRelayIdentity(identityPath: string) {
  const raw = await fs.readFile(identityPath, "utf8");
  try {
    return validateStoredIdentity(JSON.parse(raw));
  } catch (error) {
    throw new Error(`Impossible de lire ${identityPath}: identité invalide.`, { cause: error });
  }
}

export async function loadOrCreateRelayIdentity(dataDir: string): Promise<RelayIdentity> {
  const identityPath = join(dataDir, "relay-identity.json");
  await fs.mkdir(dataDir, { recursive: true, mode: 0o700 });

  try {
    const stored = await readRelayIdentity(identityPath);
    return {
      relayId: stored.relayId,
      publicKeyJwk: stored.publicKeyJwk,
      privateKeyPem: stored.privateKeyPem,
    };
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }

  const pair = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const publicKeyJwk = pair.publicKey.export({ format: "jwk" }) as JsonWebKey;
  const privateKeyPem = pair.privateKey.export({ type: "pkcs8", format: "pem" }).toString();
  const relayId = relayIdForPublicKey(publicKeyJwk);
  const stored: StoredRelayIdentity = {
    format: "quantic-relay-identity",
    version: 1,
    relayId,
    publicKeyJwk,
    privateKeyPem,
  };

  let handle: fs.FileHandle | null = null;
  try {
    handle = await fs.open(identityPath, "wx", 0o600);
    await handle.writeFile(`${JSON.stringify(stored, null, 2)}\n`, "utf8");
    await handle.sync();
    await handle.close();
    handle = null;
  } catch (error) {
    if (handle) await handle.close().catch(() => undefined);
    if ((error as NodeJS.ErrnoException).code === "EEXIST") {
      const existing = await readRelayIdentity(identityPath);
      return {
        relayId: existing.relayId,
        publicKeyJwk: existing.publicKeyJwk,
        privateKeyPem: existing.privateKeyPem,
      };
    }
    throw error;
  }

  return { relayId, publicKeyJwk, privateKeyPem };
}

export function signRelayHello(identity: RelayIdentity, endpoint: string, nonce: string): SignedRelayHello {
  if (!NONCE.test(nonce)) throw new Error("Nonce de fédération invalide.");
  const relayId = relayIdForPublicKey(identity.publicKeyJwk);
  if (relayId !== identity.relayId) throw new Error("Identité du relais incohérente.");

  const unsigned: Omit<SignedRelayHello, "p256Signature"> = {
    format: "quantic-relay-hello",
    version: 1,
    relayId,
    endpoint: normalizeEndpoint(endpoint),
    protocols: ["quantic-relay/1", "quantic-federation/1"],
    capabilities: ["direct-forward", "signed-receipt"],
    nonce,
    issuedAt: new Date().toISOString(),
    classicalSigningPublicKey: orderedPublicKey(identity.publicKeyJwk),
  };
  const signature = sign("sha256", Buffer.from(canonicalHelloText(unsigned), "utf8"), {
    key: identity.privateKeyPem,
    dsaEncoding: "ieee-p1363",
  });
  return { ...unsigned, p256Signature: signature.toString("base64") };
}

export function verifyRelayHello(value: unknown, nonce: string, expectedRelayId?: string): SignedRelayHello {
  const hello = value as Partial<SignedRelayHello> | null;
  if (!hello || hello.format !== "quantic-relay-hello" || hello.version !== 1) {
    throw new Error("Preuve de relais invalide.");
  }
  if (!NONCE.test(nonce) || hello.nonce !== nonce) throw new Error("Nonce de fédération invalide.");
  if (!hello.classicalSigningPublicKey || typeof hello.relayId !== "string" || !RELAY_ID.test(hello.relayId)) {
    throw new Error("Identité annoncée par le relais invalide.");
  }
  const calculatedRelayId = relayIdForPublicKey(hello.classicalSigningPublicKey);
  if (calculatedRelayId !== hello.relayId) throw new Error("Relay ID incohérent avec sa clé publique.");
  if (expectedRelayId && hello.relayId !== expectedRelayId) throw new Error("Relay ID inattendu.");
  if (typeof hello.endpoint !== "string") throw new Error("Endpoint du relais invalide.");
  normalizeEndpoint(hello.endpoint);
  if (!Array.isArray(hello.protocols) || hello.protocols.some((item) => typeof item !== "string")) {
    throw new Error("Protocoles du relais invalides.");
  }
  if (!Array.isArray(hello.capabilities) || hello.capabilities.some((item) => typeof item !== "string")) {
    throw new Error("Capacités du relais invalides.");
  }
  if (typeof hello.issuedAt !== "string" || Number.isNaN(Date.parse(hello.issuedAt))) {
    throw new Error("Date de preuve du relais invalide.");
  }
  if (Math.abs(Date.now() - Date.parse(hello.issuedAt)) > MAX_HELLO_AGE_MS) {
    throw new Error("Preuve du relais expirée.");
  }
  if (typeof hello.p256Signature !== "string" || !hello.p256Signature) {
    throw new Error("Signature de preuve du relais absente.");
  }
  const unsigned: Omit<SignedRelayHello, "p256Signature"> = {
    format: "quantic-relay-hello",
    version: 1,
    relayId: hello.relayId,
    endpoint: hello.endpoint,
    protocols: hello.protocols,
    capabilities: hello.capabilities,
    nonce: hello.nonce,
    issuedAt: hello.issuedAt,
    classicalSigningPublicKey: hello.classicalSigningPublicKey,
  };
  const valid = verify(
    "sha256",
    Buffer.from(canonicalHelloText(unsigned), "utf8"),
    {
      key: createPublicKey({ key: hello.classicalSigningPublicKey, format: "jwk" }),
      dsaEncoding: "ieee-p1363",
    },
    Buffer.from(hello.p256Signature, "base64"),
  );
  if (!valid) throw new Error("Signature de preuve du relais invalide.");
  return hello as SignedRelayHello;
}
