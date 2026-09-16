const CANONICAL_ADDRESS = /^[a-z0-9][a-z0-9._-]{2,31}~[0-9a-f]{10}@quantic$/;
const DEVICE_ID = /^d-[0-9a-f]{10}$/;
const REVOCATION_REASONS = new Set(["user", "lost", "compromised", "replaced"]);

function assertPublicKey(key, label) {
  if (!key || key.kty !== "EC" || key.crv !== "P-256" || !key.x || !key.y) {
    throw new Error(`${label} invalide.`);
  }
}

function publicPoint(key) {
  return `P-256:${key.x}:${key.y}`;
}

function orderedDevice(device) {
  return {
    deviceId: device.deviceId,
    label: device.label,
    publicKey: {
      kty: device.publicKey.kty,
      crv: device.publicKey.crv,
      x: device.publicKey.x,
      y: device.publicKey.y,
    },
    deviceSigningPublicKey: {
      kty: device.deviceSigningPublicKey.kty,
      crv: device.deviceSigningPublicKey.crv,
      x: device.deviceSigningPublicKey.x,
      y: device.deviceSigningPublicKey.y,
    },
    kind: device.kind,
    issuedAt: device.issuedAt,
  };
}

function orderedRevocation(revocation) {
  return {
    deviceId: revocation.deviceId,
    revokedAt: revocation.revokedAt,
    reason: revocation.reason,
  };
}

export function canonicalManifestText(payload) {
  const canonical = {
    version: payload.version,
    sequence: payload.sequence,
    canonicalAddress: payload.canonicalAddress,
    handle: payload.handle,
    fingerprint: payload.fingerprint,
    identityPublicKey: {
      kty: payload.identityPublicKey.kty,
      crv: payload.identityPublicKey.crv,
      x: payload.identityPublicKey.x,
      y: payload.identityPublicKey.y,
    },
    identitySigningPublicKey: {
      kty: payload.identitySigningPublicKey.kty,
      crv: payload.identitySigningPublicKey.crv,
      x: payload.identitySigningPublicKey.x,
      y: payload.identitySigningPublicKey.y,
    },
    devices: [...payload.devices]
      .sort((a, b) => a.deviceId.localeCompare(b.deviceId))
      .map(orderedDevice),
    revocations: [...payload.revocations]
      .sort((a, b) => a.deviceId.localeCompare(b.deviceId) || a.revokedAt.localeCompare(b.revokedAt))
      .map(orderedRevocation),
    issuedAt: payload.issuedAt,
  };
  return JSON.stringify(canonical);
}

export function activeDevices(manifest) {
  const revoked = new Set((manifest?.payload?.revocations ?? []).map((item) => item.deviceId));
  return [...(manifest?.payload?.devices ?? [])]
    .filter((device) => !revoked.has(device.deviceId))
    .sort((a, b) => a.deviceId.localeCompare(b.deviceId));
}

export function validateManifestShape(manifest) {
  if (!manifest || manifest.format !== "quantic-identity-manifest" || manifest.version !== 1) {
    throw new Error("Format de manifeste Quantic invalide.");
  }
  const payload = manifest.payload;
  if (!payload || payload.version !== 1) throw new Error("Version de manifeste Quantic invalide.");
  if (!Number.isSafeInteger(payload.sequence) || payload.sequence < 1) {
    throw new Error("Séquence de manifeste Quantic invalide.");
  }
  if (typeof payload.canonicalAddress !== "string" || !CANONICAL_ADDRESS.test(payload.canonicalAddress)) {
    throw new Error("Adresse Quantic canonique invalide.");
  }
  if (typeof payload.handle !== "string" || `${payload.handle}~${payload.fingerprint}@quantic` !== payload.canonicalAddress) {
    throw new Error("Identité canonique et empreinte incohérentes.");
  }
  assertPublicKey(payload.identityPublicKey, "Clé publique d’identité");
  assertPublicKey(payload.identitySigningPublicKey, "Clé publique de propriété");
  if (!Array.isArray(payload.devices) || payload.devices.length === 0) {
    throw new Error("Le manifeste doit contenir exactement un appareil maître.");
  }
  if (!Array.isArray(payload.revocations)) throw new Error("Liste de révocations invalide.");
  if (typeof payload.issuedAt !== "string" || Number.isNaN(Date.parse(payload.issuedAt))) {
    throw new Error("Date du manifeste invalide.");
  }
  if (typeof manifest.signature !== "string" || manifest.signature.length === 0) {
    throw new Error("Signature de manifeste absente.");
  }

  const deviceIds = new Set();
  let roots = 0;
  for (const device of payload.devices) {
    if (!device || typeof device.deviceId !== "string") throw new Error("Identifiant d’appareil invalide.");
    if (device.deviceId !== "root-1" && !DEVICE_ID.test(device.deviceId)) {
      throw new Error("Identifiant d’appareil invalide.");
    }
    if (deviceIds.has(device.deviceId)) throw new Error("Appareil dupliqué dans le manifeste.");
    deviceIds.add(device.deviceId);
    if (device.kind === "root") roots += 1;
    else if (device.kind !== "linked") throw new Error("Type d’appareil invalide.");
    if (typeof device.label !== "string" || device.label.trim().length < 2 || device.label.trim().length > 48) {
      throw new Error("Nom d’appareil invalide.");
    }
    assertPublicKey(device.publicKey, "Clé publique d’appareil");
    assertPublicKey(device.deviceSigningPublicKey, "Clé de signature d’appareil");
    if (typeof device.issuedAt !== "string" || Number.isNaN(Date.parse(device.issuedAt))) {
      throw new Error("Date d’autorisation d’appareil invalide.");
    }
  }
  if (roots !== 1) throw new Error("Le manifeste doit contenir exactement un appareil maître.");

  const revokedIds = new Set();
  for (const revocation of payload.revocations) {
    if (!revocation || typeof revocation.deviceId !== "string") throw new Error("Révocation invalide.");
    if (revokedIds.has(revocation.deviceId)) throw new Error("Révocation d’appareil dupliquée.");
    revokedIds.add(revocation.deviceId);
    if (deviceIds.has(revocation.deviceId)) {
      throw new Error(`L’appareil révoqué ${revocation.deviceId} est encore actif.`);
    }
    if (!REVOCATION_REASONS.has(revocation.reason)) throw new Error("Motif de révocation invalide.");
    if (typeof revocation.revokedAt !== "string" || Number.isNaN(Date.parse(revocation.revokedAt))) {
      throw new Error("Date de révocation invalide.");
    }
  }
  return payload;
}

export function mergeManifestState(current, incoming) {
  validateManifestShape(incoming);
  if (!current) return incoming;
  validateManifestShape(current);

  if (current.payload.canonicalAddress !== incoming.payload.canonicalAddress) {
    throw new Error("Conflit d’identité canonique.");
  }
  if (publicPoint(current.payload.identitySigningPublicKey) !== publicPoint(incoming.payload.identitySigningPublicKey)) {
    throw new Error("Conflit de clé de propriété Quantic.");
  }
  if (incoming.payload.sequence < current.payload.sequence) {
    throw new Error("Manifest rollback refusé : séquence plus ancienne.");
  }
  if (incoming.payload.sequence === current.payload.sequence) {
    if (canonicalManifestText(incoming.payload) !== canonicalManifestText(current.payload)) {
      throw new Error("Conflit de manifeste pour la même séquence.");
    }
    return current;
  }

  const incomingActive = new Set(incoming.payload.devices.map((device) => device.deviceId));
  const incomingRevocations = new Map(
    incoming.payload.revocations.map((revocation) => [revocation.deviceId, revocation]),
  );
  for (const prior of current.payload.revocations) {
    if (incomingActive.has(prior.deviceId)) {
      throw new Error(`L’appareil révoqué ${prior.deviceId} ne peut pas être réactivé.`);
    }
    const preserved = incomingRevocations.get(prior.deviceId);
    if (!preserved || preserved.revokedAt !== prior.revokedAt || preserved.reason !== prior.reason) {
      throw new Error("L’historique de révocation doit être préservé dans chaque manifeste ultérieur.");
    }
  }

  return incoming;
}
