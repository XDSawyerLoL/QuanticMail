const PREKEY_ID = /^[0-9a-f]{32}$/;

export function selectEnvelopePrivateKey(envelope, staticPrivateKey, localPreKey) {
  const keyMode = envelope?.keyMode ?? "static-fallback";
  if (keyMode === "static-fallback") {
    if (envelope?.preKeyId) throw new Error("Une enveloppe statique ne doit pas référencer de prekey.");
    if (!staticPrivateKey) throw new Error("Clé privée statique introuvable.");
    return { privateKey: staticPrivateKey, consumePreKeyId: null };
  }
  if (keyMode !== "one-time-prekey") throw new Error("Mode de clé d’enveloppe inconnu.");
  const preKeyId = String(envelope?.preKeyId ?? "");
  if (!PREKEY_ID.test(preKeyId)) throw new Error("Identifiant de prekey invalide.");
  if (!localPreKey || localPreKey.preKeyId !== preKeyId || localPreKey.state !== "unused" || !localPreKey.privateKey) {
    throw new Error("Prekey introuvable ou déjà consommée.");
  }
  return { privateKey: localPreKey.privateKey, consumePreKeyId: preKeyId };
}
