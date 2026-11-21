
import type { LocalIdentity } from "@/lib/quantic/local-db";

const VAULT_FORMAT = "quantic-identity-vault";
const VAULT_VERSION = 2;
const PBKDF2_ITERATIONS = 600_000;
const aad = (version: 1 | 2) => new TextEncoder().encode(`${VAULT_FORMAT}:v${version}`);

type VaultEnvelope = {
  format: typeof VAULT_FORMAT;
  version: 1 | 2;
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
  canonicalAddress?: string;
  fingerprint?: string;
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

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer;
}

function randomBytes(length: number) {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytes;
}

function assertPassword(password: string, minimum = 10) {
  if (typeof password !== "string" || password.length < minimum || password.length > 1024) {
    throw new Error(`Le mot de passe du coffre doit contenir entre ${minimum} et 1024 caractères.`);
  }
}

async function deriveVaultKey(password: string, salt: Uint8Array, iterations: number) {
  const passwordKey = await crypto.subtle.importKey(
    "raw",
    toArrayBuffer(new TextEncoder().encode(password)),
    "PBKDF2",
    false,
    ["deriveKey"],
  );

  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      hash: "SHA-256",
      salt: toArrayBuffer(salt),
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

function checkedBase64(value: string, min: number, max: number) {
  if (value.length > Math.ceil(max / 3) * 4 || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) {
    throw new Error("Encodage du coffre invalide.");
  }
  const bytes = fromBase64(value);
  if (bytes.length < min || bytes.length > max || toBase64(bytes) !== value) {
    throw new Error("Taille ou encodage du coffre invalide.");
  }
  return bytes;
}

async function assertKeyPairs(payload: VaultIdentityPayload) {
  const { publicKey, privateKey, signingPublicKey, signingPrivateKey } = payload;
  if (publicKey.x !== privateKey.x || publicKey.y !== privateKey.y ||
      signingPublicKey.x !== signingPrivateKey.x || signingPublicKey.y !== signingPrivateKey.y ||
      publicKey.d || signingPublicKey.d) throw new Error("Paires de clés incohérentes dans le coffre.");
  const challenge = toArrayBuffer(randomBytes(32));
  const signing = await crypto.subtle.importKey("jwk", signingPrivateKey, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
  const verification = await crypto.subtle.importKey("jwk", signingPublicKey, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
  const signature = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, signing, challenge);
  if (!await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, verification, signature, challenge)) {
    throw new Error("Paire de signature incohérente dans le coffre.");
  }
  // Existing Quantic ECDH JWKs have key_ops=["deriveKey"], not "deriveBits".
  const own = await crypto.subtle.importKey("jwk", privateKey, { name: "ECDH", namedCurve: "P-256" }, false, ["deriveKey"]);
  const pub = await crypto.subtle.importKey("jwk", publicKey, { name: "ECDH", namedCurve: "P-256" }, false, []);
  const ephemeral = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveKey"]);
  const a = await crypto.subtle.deriveKey({ name: "ECDH", public: ephemeral.publicKey }, own, { name: "AES-GCM", length: 256 }, false, ["encrypt"]);
  const b = await crypto.subtle.deriveKey({ name: "ECDH", public: pub }, ephemeral.privateKey, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
  const iv = toArrayBuffer(randomBytes(12));
  const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, a, challenge);
  await crypto.subtle.decrypt({ name: "AES-GCM", iv }, b, encrypted);
}

function parseEnvelope(text: string): VaultEnvelope {
  if (typeof text !== "string" || text.length > 1_000_000) throw new Error("Taille du coffre invalide.");
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new Error("Ce fichier n’est pas un coffre Quantic valide.");
  }

  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("Format de coffre Quantic non reconnu.");
  const envelope = parsed as Partial<VaultEnvelope>;
  if (
    envelope.format !== VAULT_FORMAT ||
    (envelope.version !== 1 && envelope.version !== 2) ||
    envelope.kdf?.name !== "PBKDF2" ||
    envelope.kdf.hash !== "SHA-256" ||
    envelope.cipher?.name !== "AES-GCM" ||
    typeof envelope.kdf.iterations !== "number" || !Number.isSafeInteger(envelope.kdf.iterations) ||
    typeof envelope.kdf.salt !== "string" ||
    typeof envelope.cipher.iv !== "string" ||
    typeof envelope.ciphertext !== "string"
  ) {
    throw new Error("Format de coffre Quantic non reconnu.");
  }
  if (envelope.kdf.iterations < 100_000 || envelope.kdf.iterations > 2_000_000) {
    throw new Error("Paramètres de dérivation du coffre refusés.");
  }
  checkedBase64(envelope.kdf.salt, 16, 16);
  checkedBase64(envelope.cipher.iv, 12, 12);
  checkedBase64(envelope.ciphertext, 17, 750_000);
  return envelope as VaultEnvelope;
}

async function verifiedAddress(handle: string, signingPublicKey: JsonWebKey, canonicalAddress: string) {
  if (!/^[a-z0-9][a-z0-9._-]{2,31}$/.test(handle)) throw new Error("Identifiant Quantic invalide dans le coffre.");
  const match = /^([a-z0-9][a-z0-9._-]{2,31})~([0-9a-f]{10}|[0-9a-f]{32})@quantic$/.exec(canonicalAddress);
  if (!match || match[1] !== handle) throw new Error("Adresse canonique invalide dans le coffre.");
  const fingerprint = match[2];
  const bytes = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(`P-256:${signingPublicKey.x}:${signingPublicKey.y}`)));
  const digest = Array.from(bytes, byte => byte.toString(16).padStart(2, "0")).join("");
  if (!digest.startsWith(fingerprint)) throw new Error("Adresse et clé de propriété incohérentes dans le coffre.");
  return { canonicalAddress, fingerprint };
}

export async function exportIdentityVault(identity: LocalIdentity, password: string) {
  assertPassword(password, 14);
  if (identity.role === "secondary" || !identity.signingPublicKey || !identity.signingPrivateKey || !identity.canonicalAddress || !identity.fingerprint) {
    throw new Error("L’identité doit être migrée vers Quantic V0.7 avant export.");
  }

  const names = await verifiedAddress(identity.handle, identity.signingPublicKey, identity.canonicalAddress);
  if (names.fingerprint !== identity.fingerprint) throw new Error("Empreinte locale incohérente dans le coffre.");
  const payload: VaultIdentityPayload = {
    handle: identity.handle,
    ...names,
    publicKey: identity.publicKey,
    privateKey: identity.privateKey,
    signingPublicKey: identity.signingPublicKey,
    signingPrivateKey: identity.signingPrivateKey,
    createdAt: identity.createdAt,
  };

  await assertKeyPairs(payload);
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const key = await deriveVaultKey(password, salt, PBKDF2_ITERATIONS);
  const plaintext = new TextEncoder().encode(JSON.stringify(payload));
  const ciphertext = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: toArrayBuffer(iv),
      additionalData: toArrayBuffer(aad(VAULT_VERSION)),
    },
    key,
    toArrayBuffer(plaintext),
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

export async function importIdentityVault(text: string, password: string, expectedAddress?: string) {
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
        iv: toArrayBuffer(fromBase64(envelope.cipher.iv)),
        additionalData: toArrayBuffer(aad(envelope.version)),
      },
      key,
      toArrayBuffer(fromBase64(envelope.ciphertext)),
    );
    const payload = JSON.parse(new TextDecoder().decode(plaintext)) as VaultIdentityPayload;

    if (!/^[a-z0-9][a-z0-9._-]{2,31}$/.test(payload.handle ?? "")) {
      throw new Error("Identifiant Quantic invalide dans le coffre.");
    }
    assertPublicJwk(payload.publicKey, "Clé publique de chiffrement");
    assertPrivateJwk(payload.privateKey, "Clé privée de chiffrement");
    assertPublicJwk(payload.signingPublicKey, "Clé publique de propriété");
    assertPrivateJwk(payload.signingPrivateKey, "Clé privée de propriété");

    await assertKeyPairs(payload);
    const expected = expectedAddress?.trim();
    if (envelope.version === 1 && !expected) {
      throw new Error("Ancien format : renseignez l’adresse Quantic canonique complète d’origine dans le coffre.");
    }
    if (envelope.version === 2 && (typeof payload.canonicalAddress !== "string" || typeof payload.fingerprint !== "string")) {
      throw new Error("Adresse ou empreinte manquante dans le coffre.");
    }
    const recorded = envelope.version === 1 ? expected : payload.canonicalAddress;
    if (!recorded) throw new Error("Adresse manquante dans le coffre.");
    const names = await verifiedAddress(payload.handle, payload.signingPublicKey, recorded);
    if (envelope.version === 2 && names.fingerprint !== payload.fingerprint) throw new Error("Empreinte incohérente dans le coffre.");
    if (expected && expected !== names.canonicalAddress) throw new Error("Adresse de récupération différente dans le coffre.");
    return {
      handle: payload.handle,
      address: `${payload.handle}@quantic`,
      ...names,
      role: "root" as const,
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
