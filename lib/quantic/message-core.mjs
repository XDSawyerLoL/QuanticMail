function requireText(value, label) {
  if (typeof value !== "string" || !value) throw new Error(`${label} invalide.`);
  return value;
}

export function localMessageFromEnvelope(payload, envelope) {
  if (!payload || typeof payload !== "object" || !envelope || typeof envelope !== "object") {
    throw new Error("Message Quantic invalide.");
  }
  const id = requireText(payload.id, "Identifiant de message");
  const from = requireText(payload.from, "Expéditeur logique");
  const to = requireText(payload.to, "Destinataire logique");
  const subject = requireText(payload.subject, "Objet");
  const body = typeof payload.body === "string" ? payload.body : (() => { throw new Error("Corps de message invalide."); })();
  const createdAt = requireText(payload.createdAt || envelope.createdAt, "Date du message");
  const transportFrom = requireText(envelope.from, "Expéditeur de transport");
  const transportTo = requireText(envelope.to, "Destinataire de transport");
  if (from !== transportFrom) throw new Error("Expéditeur logique incohérent avec l’enveloppe.");

  if (payload.syncCopy === true) {
    if (transportTo !== from) throw new Error("Copie de synchronisation invalide : elle doit revenir à l’identité émettrice.");
    return { id, direction: "out", from, to, subject, body, createdAt };
  }

  if (to !== transportTo) throw new Error("Destinataire logique incohérent avec l’enveloppe.");
  return { id, direction: "in", from, to, subject, body, createdAt };
}
