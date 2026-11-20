// Local Quantic ID -> Quantic Mail mailbox ownership binding.
// This is not a key derivation and does not claim that the QID private key
// can decrypt a mailbox created in a different browser profile.
const QID = /^qid_[0-9a-f]{32}$/;

export function decideQuanticIdMailboxAccess(mailIdentity, keyId) {
  if (!QID.test(keyId ?? "")) {
    return { kind: "invalid" };
  }
  if (!mailIdentity) return { kind: "mailbox-absent" };
  const owner = mailIdentity.quanticIdKeyId;
  if (!owner) return { kind: "unbound", address: mailIdentity.canonicalAddress ?? mailIdentity.address };
  if (owner !== keyId) return { kind: "mismatch" };
  return { kind: "ready", address: mailIdentity.canonicalAddress ?? mailIdentity.address };
}

export function bindMailboxToQuanticId(mailIdentity, verifiedKeyId, now = new Date().toISOString()) {
  const decision = decideQuanticIdMailboxAccess(mailIdentity, verifiedKeyId);
  if (decision.kind === "invalid") throw new Error("Quantic ID invalide.");
  if (decision.kind === "mailbox-absent") throw new Error("Les clés de la boîte sont absentes de ce PC.");
  if (decision.kind === "mismatch") throw new Error("Cette boîte est déjà associée à un autre Quantic ID.");
  if (!mailIdentity?.canonicalAddress || !mailIdentity?.privateKey ||
      (!mailIdentity.signingPrivateKey && !mailIdentity.deviceCertificate)) {
    throw new Error("La boîte locale n'est pas complètement installée ou autorisée.");
  }
  if (decision.kind === "ready") return mailIdentity;
  if (!Number.isFinite(Date.parse(now))) throw new Error("Date d'association invalide.");
  return { ...mailIdentity, quanticIdKeyId: verifiedKeyId, quanticIdBoundAt: now };
}
