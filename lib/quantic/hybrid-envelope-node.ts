import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createPrivateKey,
  createPublicKey,
  diffieHellman,
  generateKeyPairSync,
  hkdfSync,
  randomBytes,
} from "node:crypto";

import {
  canonicalHybridContext,
  hybridAad,
  hybridKdfInfo,
  hybridKdfInput,
  HYBRID_CRYPTO_SUITE,
  type HybridEnvelopeContext,
} from "./hybrid-crypto.ts";
import { mlKemDecapsulate, mlKemEncapsulate } from "./pqc-runtime-node.ts";

export { HYBRID_CRYPTO_SUITE };
export type { HybridEnvelopeContext };

export type HybridEncryptedEnvelope = {
  cryptoSuite: typeof HYBRID_CRYPTO_SUITE;
  keyMode: "hybrid-static-fallback";
  classicalEphemeralPublicKey: JsonWebKey;
  pqKemCiphertext: string;
  iv: string;
  ciphertext: string;
};

function encode(value: Uint8Array | Buffer) {
  return Buffer.from(value).toString("base64url");
}

function decode(value: string, label: string) {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) throw new Error(`${label} base64url invalide.`);
  return Buffer.from(value, "base64url");
}

function deriveHybridKeyNode(classicalSecret: Uint8Array, pqSecret: Uint8Array, context: HybridEnvelopeContext) {
  const ikm = Buffer.from(hybridKdfInput(classicalSecret, pqSecret));
  const info = Buffer.from(hybridKdfInfo(context));
  const salt = createHash("sha256")
    .update(`quantic-hybrid-kdf-salt-v1\n${canonicalHybridContext(context)}`, "utf8")
    .digest();
  return Buffer.from(hkdfSync("sha256", ikm, salt, info, 32));
}

export function encryptHybridEnvelopeNode(input: {
  recipientClassicalPublicKey: JsonWebKey;
  recipientMlKemPublicKeySpki: string;
  context: HybridEnvelopeContext;
  payload: unknown;
}): HybridEncryptedEnvelope {
  const recipientPublicKey = createPublicKey({ key: input.recipientClassicalPublicKey, format: "jwk" });
  if (recipientPublicKey.asymmetricKeyType !== "ec") throw new Error("Clé P-256 destinataire invalide.");

  const ephemeral = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const classicalSecret = diffieHellman({ privateKey: ephemeral.privateKey, publicKey: recipientPublicKey });
  if (classicalSecret.byteLength !== 32) throw new Error("Secret ECDH P-256 inattendu.");

  const pq = mlKemEncapsulate(input.recipientMlKemPublicKeySpki);
  const key = deriveHybridKeyNode(classicalSecret, pq.sharedSecret, input.context);
  const iv = randomBytes(12);
  const aad = Buffer.from(hybridAad(input.context));
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  cipher.setAAD(aad);
  const encrypted = Buffer.concat([
    cipher.update(Buffer.from(JSON.stringify(input.payload), "utf8")),
    cipher.final(),
  ]);
  const combinedCiphertext = Buffer.concat([encrypted, cipher.getAuthTag()]);

  return {
    cryptoSuite: HYBRID_CRYPTO_SUITE,
    keyMode: "hybrid-static-fallback",
    classicalEphemeralPublicKey: ephemeral.publicKey.export({ format: "jwk" }),
    pqKemCiphertext: pq.ciphertext,
    iv: encode(iv),
    ciphertext: encode(combinedCiphertext),
  };
}

export function decryptHybridEnvelopeNode(input: {
  recipientClassicalPrivateKey: JsonWebKey;
  recipientMlKemPrivateKeyPkcs8: string;
  context: HybridEnvelopeContext;
  envelope: HybridEncryptedEnvelope;
}) {
  if (input.envelope.cryptoSuite !== HYBRID_CRYPTO_SUITE || input.envelope.keyMode !== "hybrid-static-fallback") {
    throw new Error("Suite hybride Quantic non prise en charge.");
  }

  const recipientPrivateKey = createPrivateKey({ key: input.recipientClassicalPrivateKey, format: "jwk" });
  const ephemeralPublicKey = createPublicKey({ key: input.envelope.classicalEphemeralPublicKey, format: "jwk" });
  if (recipientPrivateKey.asymmetricKeyType !== "ec" || ephemeralPublicKey.asymmetricKeyType !== "ec") {
    throw new Error("Clé P-256 hybride invalide.");
  }

  const classicalSecret = diffieHellman({ privateKey: recipientPrivateKey, publicKey: ephemeralPublicKey });
  if (classicalSecret.byteLength !== 32) throw new Error("Secret ECDH P-256 inattendu.");
  const pqSecret = mlKemDecapsulate(input.recipientMlKemPrivateKeyPkcs8, input.envelope.pqKemCiphertext);
  const key = deriveHybridKeyNode(classicalSecret, pqSecret, input.context);

  const combined = decode(input.envelope.ciphertext, "Ciphertext hybride");
  if (combined.byteLength <= 16) throw new Error("Ciphertext hybride tronqué.");
  const encrypted = combined.subarray(0, combined.byteLength - 16);
  const authTag = combined.subarray(combined.byteLength - 16);
  const decipher = createDecipheriv("aes-256-gcm", key, decode(input.envelope.iv, "IV hybride"));
  decipher.setAAD(Buffer.from(hybridAad(input.context)));
  decipher.setAuthTag(authTag);
  const plaintext = Buffer.concat([decipher.update(encrypted), decipher.final()]);
  return JSON.parse(plaintext.toString("utf8"));
}
