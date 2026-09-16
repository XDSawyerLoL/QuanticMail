import { fingerprintPublicKey } from "@/lib/quantic/crypto";
import type { LocalIdentity } from "@/lib/quantic/local-db";

const VAULT_FORMAT = "quantic-identity-vault";
const VAULT_VERSION = 1;
const PBKDF2_ITERATIONS = 250_000;
const AAD = new TextEncoder().encode(`${VAULT_FORMAT}:v${VAULT_VERSION}`);

type VaultEnvelope = {
  format: typeof VAULT_FORMAT;
  version: typeof VAULT_VERSION;
  createdAt: string;
  kdf: {
    name: "PBKDF2";
    hash: "SHA-256";
    iterations: number;
    salt: string;
  };
  cipher: {
    name: "AES-GCM";
    iv: string;
  };
  ciphertext: string;
};

type VaultIdentityPayload = {
  handle: string;
  publicKey: JsonWebKey;
  privateKey: JsonWebKey;
  signingPublicKey: JsonWebKey;
  signingPrivateKey: JsonWebKey;
  createdAt: string;
};

function toBase64(bytes: Uint8Array) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function fromBase64(value: string) {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function randomBytes(length: number) {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytes;
}

function assertPassword(password: string) {
  if (password.length < 10) {
    throw new Error("Le mot de passe du coffre doit contenir au moins 10 caractères.");
  }
}

async function deriveVaultKey(password: string, salt: Uint8Array, iterations: number) {
  const passwordKey = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveKey"],
  );

  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      hash: "SHA-256",
      salt,
      iterations,
    },
    passwordKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

function assertPrivateJwk(key: JsonWebKey, label: string) {
  if (key.kty !== "EC" || key.crv !== "P-256" || !key.x || !key.y || !key.d) {
    throw new Error(`${label} invalide dans le coffre Quantic.`);
  }
}

function assertPublicJwk(key: JsonWebKey, label: string) {
  if (key.kty !== "EC" || key.crv !== "P-256" || !key.x || !key.y) {
    throw new Error(`${label} invalide dans le coffre Quantic.`);
  }
}

function parseEnvelope(text: string): VaultEnvelope {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new Error("Ce fichier n’est pas un coffre Quantic valide.");
  }

  const envelope = parsed as Partial<VaultEnvelope>;
  if (
    envelope.format !== VAULT_FORMAT ||
    envelope.version !== VAULT_VERSION ||
    envelope.kdf?.name !== "PBKDF2" ||
    envelope.kdf.hash !== "SHA-256" ||
    envelope.cipher?.name !== "AES-GCM" ||
    typeof envelope.kdf.iterations !== "number" ||
    typeof envelope.kdf.salt !== "string" ||
    typeof envelope.cipher.iv !== "string" ||
    typeof envelope.ciphertext !== "string"
  ) {
    throw new Error("Format de coffre Quantic non reconnu.");
  }
  if (envelope.kdf.iterations < 100_000 || envelope.kdf.iterations > 2_000_000) {
    throw new Error("Paramètres de dérivation du coffre refusés.");
  }
  return envelope as VaultEnvelope;
}

export async function exportIdentityVault(identity: LocalIdentity, password: string) {
  assertPassword(password);
  if (!identity.signingPublicKey || !identity.signingPrivateKey) {
    throw new Error("L’identité doit être migrée vers Quantic V0.7 avant export.");
  }

  const payload: VaultIdentityPayload = {
    handle: identity.handle,
    publicKey: identity.publicKey,
    privateKey: identity.privateKey,
    signingPublicKey: identity.signingPublicKey,
    signingPrivateKey: identity.signingPrivateKey,
    createdAt: identity.createdAt,
  };

  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const key = await deriveVaultKey(password, salt, PBKDF2_ITERATIONS);
  const plaintext = new TextEncoder().encode(JSON.stringify(payload));
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: AAD },
    key,
    plaintext,
  );

  const envelope: VaultEnvelope = {
    format: VAULT_FORMAT,
    version: VAULT_VERSION,
    createdAt: new Date().toISOString(),
    kdf: {
      name: "PBKDF2",
      hash: "SHA-256",
      iterations: PBKDF2_ITERATIONS,
      salt: toBase64(salt),
    },
    cipher: {
      name: "AES-GCM",
      iv: toBase64(iv),
    },
    ciphertext: toBase64(new Uint8Array(ciphertext)),
  };

  return JSON.stringify(envelope, null, 2);
}

export async function importIdentityVault(text: string, password: string) {
  assertPassword(password);
  const envelope = parseEnvelope(text);

  try {
    const key = await deriveVaultKey(
      password,
      fromBase64(envelope.kdf.salt),
      envelope.kdf.iterations,
    );
    const plaintext = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: fromBase64(envelope.cipher.iv),
        additionalData: AAD,
      },
      key,
      fromBase64(envelope.ciphertext),
    );
    const payload = JSON.parse(new TextDecoder().decode(plaintext)) as VaultIdentityPayload;

    if (!/^[a-z0-9][a-z0-9._-]{2,31}$/.test(payload.handle ?? "")) {
      throw new Error("Identifiant Quantic invalide dans le coffre.");
    }
    assertPublicJwk(payload.publicKey, "Clé publique de chiffrement");
    assertPrivateJwk(payload.privateKey, "Clé privée de chiffrement");
    assertPublicJwk(payload.signingPublicKey, "Clé publique de propriété");
    assertPrivateJwk(payload.signingPrivateKey, "Clé privée de propriété");

    const fingerprint = await fingerprintPublicKey(payload.signingPublicKey);
    return {
      handle: payload.handle,
      address: `${payload.handle}@quantic`,
      canonicalAddress: `${payload.handle}~${fingerprint}@quantic`,
      fingerprint,
      publicKey: payload.publicKey,
      privateKey: payload.privateKey,
      signingPublicKey: payload.signingPublicKey,
      signingPrivateKey: payload.signingPrivateKey,
      createdAt: payload.createdAt || new Date().toISOString(),
    } satisfies Omit<LocalIdentity, "authToken">;
  } catch (error) {
    if (error instanceof Error && error.message.includes("dans le coffre")) throw error;
    throw new Error("Impossible d’ouvrir le coffre : mot de passe incorrect ou fichier altéré.");
  }
}
