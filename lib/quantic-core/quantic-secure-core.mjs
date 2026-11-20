/**
 * Quantic Secure Core (QSC1) — portable binary cryptographic record format.
 * Host-independent: uses W3C Web Crypto and requires caller-supplied, non-extractable
 * HKDF root key from an independently protected Quantic ID unlock provider.
 * NOT a password manager, operating-system keyring, or complete Identity Vault.
 */
export const FORMAT = 'QSC1';
export const VERSION = 1;
const MAGIC = new Uint8Array([0x51, 0x53, 0x43, 0x31]);
const HEADER_SIZE = 40;
const TAG_BYTES = 16;
const MAX_PLAINTEXT_BYTES = 8 * 1024 * 1024;
const encoder = new TextEncoder();

function ensureWebCrypto(cryptoImpl) {
  if (!cryptoImpl || typeof cryptoImpl.getRandomValues !== 'function' || !cryptoImpl.subtle) {
    throw new Error('Web Crypto standard requis pour Quantic Secure Core.');
  }
  return cryptoImpl;
}

function scopeInformation(identityId, namespace, recordId) {
  for (const field of [identityId, namespace, recordId]) {
    if (typeof field !== 'string' || field.length < 1 || field.length > 240 ||
      !/^[A-Za-z0-9._~:@-]+$/.test(field)) {
      throw new Error('Contexte du coffre Quantic invalide.');
    }
  }
  return encoder.encode(JSON.stringify(['quantic-secure-core', VERSION, identityId, namespace, recordId]));
}

function concat(a, b) {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

function assertRootKey(key) {
  if (!key || key.type !== 'secret' || key.algorithm?.name !== 'HKDF' ||
      key.extractable !== false || !key.usages?.includes('deriveKey')) {
    throw new Error('Clé racine HKDF non exportable requise.');
  }
}

export async function importVolatileRootKey(secretBytes, cryptoImpl = globalThis.crypto) {
  const c = ensureWebCrypto(cryptoImpl);
  if (!(secretBytes instanceof Uint8Array) || secretBytes.byteLength !== 32) {
    throw new Error('Secret de déverrouillage externe de 256 bits requis.');
  }
  // Caller must wipe its original secret buffer after import when possible.
  // CryptoKey is nonextractable, but not necessarily hardware-backed.
  return c.subtle.importKey('raw', secretBytes, 'HKDF', false, ['deriveKey']);
}

async function deriveRecordKey(rootKey, salt, scope, c) {
  assertRootKey(rootKey);
  return c.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt, info: scope },
    rootKey, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

function newHeader(salt, nonce, encryptedLength) {
  const h = new Uint8Array(HEADER_SIZE);
  h.set(MAGIC, 0);
  h[4] = VERSION;
  h[5] = 1; // HKDF-SHA256 + AES-256-GCM
  h.set(salt, 8);
  h.set(nonce, 24);
  new DataView(h.buffer).setUint32(36, encryptedLength, false);
  return h;
}

function readHeader(file) {
  if (!(file instanceof Uint8Array) || file.length < HEADER_SIZE + TAG_BYTES ||
      file.length > HEADER_SIZE + MAX_PLAINTEXT_BYTES + TAG_BYTES) {
    throw new Error('Fichier de coffre Quantic tronqué ou trop volumineux.');
  }
  const h = file.subarray(0, HEADER_SIZE);
  if (!MAGIC.every((b, index) => h[index] === b) || h[4] !== VERSION || h[5] !== 1 ||
      h[6] !== 0 || h[7] !== 0) {
    throw new Error('Format de coffre Quantic non reconnu.');
  }
  if (new DataView(h.buffer, h.byteOffset, h.byteLength).getUint32(36, false) !== file.length - HEADER_SIZE) {
    throw new Error('Longueur de coffre Quantic incohérente.');
  }
  return h;
}

/** Serialize secret bytes into an opaque .qsc binary record. */
export async function sealRecord({ rootKey, identityId, namespace, recordId, plaintext,
  cryptoImpl = globalThis.crypto }) {
  const c = ensureWebCrypto(cryptoImpl);
  const scope = scopeInformation(identityId, namespace, recordId);
  if (!(plaintext instanceof Uint8Array) || plaintext.length > MAX_PLAINTEXT_BYTES) {
    throw new Error('Charge utile du coffre Quantic invalide ou trop volumineuse.');
  }
  const salt = c.getRandomValues(new Uint8Array(16));
  const nonce = c.getRandomValues(new Uint8Array(12));
  const header = newHeader(salt, nonce, plaintext.length + TAG_BYTES);
  const key = await deriveRecordKey(rootKey, salt, scope, c);
  const ciphertext = new Uint8Array(await c.subtle.encrypt({
    name: 'AES-GCM', iv: nonce, additionalData: concat(header, scope), tagLength: 128,
  }, key, plaintext));
  if (ciphertext.length !== plaintext.length + TAG_BYTES) throw new Error('Chiffrement Quantic inattendu.');
  return concat(header, ciphertext);
}

/** Decrypt only when both unlock key and authenticated record identity match. */
export async function unsealRecord({ rootKey, identityId, namespace, recordId, file,
  cryptoImpl = globalThis.crypto }) {
  const c = ensureWebCrypto(cryptoImpl);
  const scope = scopeInformation(identityId, namespace, recordId);
  const header = readHeader(file);
  const key = await deriveRecordKey(rootKey, header.subarray(8, 24), scope, c);
  try {
    return new Uint8Array(await c.subtle.decrypt({
      name: 'AES-GCM', iv: header.subarray(24, 36),
      additionalData: concat(header, scope), tagLength: 128,
    }, key, file.subarray(HEADER_SIZE)));
  } catch {
    throw new Error('Coffre Quantic inaccessible : secret, contexte ou intégrité invalide.');
  }
}
