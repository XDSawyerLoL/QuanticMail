function toBase64(bytes) {
  if (typeof Buffer !== "undefined") return Buffer.from(bytes).toString("base64");
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function fromBase64(value) {
  if (typeof Buffer !== "undefined") return new Uint8Array(Buffer.from(value, "base64"));
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function asArrayBuffer(bytes) {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer;
}

export async function encryptForRecipientCore(recipientPublicJwk, payload) {
  const recipientPublicKey = await globalThis.crypto.subtle.importKey(
    "jwk",
    recipientPublicJwk,
    { name: "ECDH", namedCurve: "P-256" },
    false,
    [],
  );
  const ephemeral = await globalThis.crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveKey"],
  );
  const aesKey = await globalThis.crypto.subtle.deriveKey(
    { name: "ECDH", public: recipientPublicKey },
    ephemeral.privateKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt"],
  );
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
  const plaintext = new TextEncoder().encode(JSON.stringify(payload));
  const ciphertext = await globalThis.crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    aesKey,
    plaintext,
  );
  return {
    ciphertext: toBase64(new Uint8Array(ciphertext)),
    iv: toBase64(iv),
    ephemeralPublicKey: await globalThis.crypto.subtle.exportKey("jwk", ephemeral.publicKey),
  };
}

export async function decryptEnvelopeCore(privateJwk, envelope) {
  const privateKey = await globalThis.crypto.subtle.importKey(
    "jwk",
    privateJwk,
    { name: "ECDH", namedCurve: "P-256" },
    false,
    ["deriveKey"],
  );
  const ephemeralPublicKey = await globalThis.crypto.subtle.importKey(
    "jwk",
    envelope.ephemeralPublicKey,
    { name: "ECDH", namedCurve: "P-256" },
    false,
    [],
  );
  const aesKey = await globalThis.crypto.subtle.deriveKey(
    { name: "ECDH", public: ephemeralPublicKey },
    privateKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"],
  );
  const plaintext = await globalThis.crypto.subtle.decrypt(
    { name: "AES-GCM", iv: asArrayBuffer(fromBase64(envelope.iv)) },
    aesKey,
    asArrayBuffer(fromBase64(envelope.ciphertext)),
  );
  return JSON.parse(new TextDecoder().decode(plaintext));
}
