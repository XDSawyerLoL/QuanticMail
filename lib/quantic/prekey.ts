import { signChallenge } from "@/lib/quantic/crypto";
import {
  canonicalPreKeyText,
  verifyPreKeySignature,
  type SignedPreKeyRecord,
} from "@/lib/quantic/prekey-core.mjs";
import type { LocalIdentity } from "@/lib/quantic/local-db";

export type LocalPreKey = SignedPreKeyRecord & {
  privateKey: JsonWebKey;
  state: "unused" | "claimed";
};

function randomHex(bytes = 16) {
  const value = crypto.getRandomValues(new Uint8Array(bytes));
  return Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export async function generateOneTimePreKey(
  identity: LocalIdentity,
  lifetimeMs = 7 * 24 * 60 * 60 * 1000,
): Promise<LocalPreKey> {
  if (!identity.canonicalAddress || !identity.deviceId || !identity.deviceSigningPrivateKey) {
    throw new Error("Cet appareil ne possède pas de clé de signature d’appareil V1.1.");
  }
  const pair = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveKey"],
  );
  const createdAt = new Date().toISOString();
  const expiresAt = new Date(Date.now() + lifetimeMs).toISOString();
  const unsigned: SignedPreKeyRecord = {
    version: 1,
    canonicalAddress: identity.canonicalAddress,
    deviceId: identity.deviceId,
    preKeyId: randomHex(),
    publicKey: await crypto.subtle.exportKey("jwk", pair.publicKey),
    createdAt,
    expiresAt,
    signature: "",
  };
  const signature = await signChallenge(
    identity.deviceSigningPrivateKey,
    canonicalPreKeyText(unsigned),
  );
  return {
    ...unsigned,
    signature,
    privateKey: await crypto.subtle.exportKey("jwk", pair.privateKey),
    state: "unused",
  };
}

export function publicPreKey(local: LocalPreKey): SignedPreKeyRecord {
  return {
    version: local.version,
    canonicalAddress: local.canonicalAddress,
    deviceId: local.deviceId,
    preKeyId: local.preKeyId,
    publicKey: local.publicKey,
    createdAt: local.createdAt,
    expiresAt: local.expiresAt,
    signature: local.signature,
  };
}

export { verifyPreKeySignature };
export type { SignedPreKeyRecord };
