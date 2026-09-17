import { validateCryptoProfileShape } from "./crypto-profile-core.mjs";
import { HYBRID_CRYPTO_SUITE } from "./hybrid-crypto.ts";

function isHybridEnvelope(envelope) {
  return envelope?.keyMode === "hybrid-one-time-prekey" || envelope?.keyMode === "hybrid-static-fallback";
}

export function resolveCryptoPolicy(profile) {
  if (!profile) {
    return {
      mode: "classical-allowed",
      requireHybrid: false,
      profile: null,
    };
  }
  const validated = validateCryptoProfileShape(profile);
  return {
    mode: validated.payload.policy,
    requireHybrid: validated.payload.policy === "hybrid-required",
    profile: validated,
  };
}

export function assertEnvelopeMeetsCryptoPolicy(envelope, profile) {
  const policy = resolveCryptoPolicy(profile);
  const hybrid = isHybridEnvelope(envelope);

  if (!policy.profile) {
    if (hybrid) {
      throw new Error("Un Crypto Profile V2 vérifié est requis pour une enveloppe hybride post-quantique.");
    }
    return { ...policy, hybrid: false, pqDevice: null };
  }

  if (policy.profile.payload.canonicalAddress !== envelope.from) {
    throw new Error("Le Crypto Profile V2 ne correspond pas à l’identité expéditrice.");
  }

  const pqDevice = policy.profile.payload.devices.find((device) => device.deviceId === envelope.fromDeviceId);
  if (!pqDevice) {
    throw new Error("L’appareil expéditeur est absent du Crypto Profile V2.");
  }

  if (!hybrid) {
    if (policy.requireHybrid) {
      throw new Error("Downgrade Crypto V2 refusé : cette identité exige une enveloppe hybride post-quantique.");
    }
    if (envelope.cryptoSuite === HYBRID_CRYPTO_SUITE || envelope.pqKemCiphertext) {
      throw new Error("Enveloppe Crypto V2 incohérente : mode classique avec paramètres hybrides.");
    }
    return { ...policy, hybrid: false, pqDevice: null };
  }

  if (envelope.cryptoSuite !== HYBRID_CRYPTO_SUITE) {
    throw new Error("Suite cryptographique hybride Quantic invalide.");
  }
  if (!envelope.classicalEphemeralPublicKey || !envelope.pqKemCiphertext) {
    throw new Error("Enveloppe hybride incomplète : P-256 et ML-KEM-768 sont obligatoires.");
  }
  if (!envelope.signatures?.mlDsa65Device) {
    throw new Error("Signature ML-DSA-65 de l’appareil obligatoire pour une enveloppe hybride.");
  }

  return { ...policy, hybrid: true, pqDevice };
}
