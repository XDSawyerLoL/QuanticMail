/**
 * Quantic ID presence for a compatible SITE BACKEND (Node.js).
 * Memory only; no database, disk, central Quantic server or Quantic Network.
 * A cryptographically fresh Quantic ID proof is required per activation/renewal.
 *
 * A site must still implement its own privacy policy, HTTP no-store response
 * headers, authorization checks, browser lock notification and optional
 * persistent records. This class NEVER stores user consent/persistent data.
 */
import { createHash, createPublicKey, randomBytes, verify } from 'node:crypto';

export const DEFAULT_PRESENCE_TTL_MS = 10_000;
const CHALLENGE_TTL_MS = 10_000;
const MAX_PROOF_AGE_MS = 5_000;
const QID_RE = /^qid_[0-9a-f]{32}$/;

function nonempty(value, max = 240) {
  if (typeof value !== 'string' || value.length < 1 || value.length > max) {
    throw new Error('Champ Quantic ID invalide.');
  }
  return value;
}
function requireAudience(value) {
  const url = new URL(nonempty(value, 320));
  const loopback = (url.hostname === 'localhost' || url.hostname === '127.0.0.1');
  if (!((url.protocol === 'https:') || (loopback && url.protocol === 'http:')) ||
      url.username || url.password || url.pathname !== '/' || url.search || url.hash) {
    throw new Error('Origine HTTPS Quantic ID requise.');
  }
  return url.origin;
}

/**
 * Verify an Identity Vault /v1/assert signed payload for a one-use challenge.
 * No network lookup required; the Quantic ID is derived from the public key.
 * Display name and permissions are NOT trusted merely because of this proof.
 */
export function createQuanticSiteProofVerifier({ audience, now = Date.now } = {}) {
  const expectedAudience = requireAudience(audience);
  return async function verifyProof({ proof, challenge }) {
    if (!proof || typeof proof !== 'object' || proof.version !== 1 ||
        !QID_RE.test(proof.keyId) || typeof proof.payload !== 'string' ||
        proof.payload.length > 4096 ||
        typeof proof.publicKey !== 'string' || proof.publicKey.length > 2048 ||
        typeof proof.signature !== 'string' || proof.signature.length > 2048) {
      throw new Error('Preuve Quantic ID invalide.');
    }
    let signed;
    try { signed = JSON.parse(proof.payload); } catch { throw new Error('Preuve Quantic ID illisible.'); }
    if (!signed || signed.version !== 1 || signed.keyId !== proof.keyId ||
        signed.challenge !== challenge || signed.audience !== expectedAudience ||
        typeof signed.issuedAt !== 'string') throw new Error('Preuve Quantic ID hors contexte.');
    const signedAtMs = Date.parse(signed.issuedAt);
    if (!Number.isFinite(signedAtMs) || Math.abs(now() - signedAtMs) > MAX_PROOF_AGE_MS) {
      throw new Error('Preuve Quantic ID expirée.');
    }
    if (!/^[A-Za-z0-9_-]+$/.test(proof.publicKey) ||
        !/^[A-Za-z0-9_-]+$/.test(proof.signature)) {
      throw new Error('Encodage de la preuve Quantic ID invalide.');
    }
    const der = Buffer.from(proof.publicKey, 'base64url');
    const keyId = 'qid_' + createHash('sha256').update(der).digest('hex').slice(0,32);
    if (keyId !== proof.keyId) throw new Error('Empreinte Quantic ID incohérente.');
    let publicKey;
    try { publicKey = createPublicKey({key:der,format:'der',type:'spki'}); }
    catch { throw new Error('Clé publique Quantic ID invalide.'); }
    let options, algorithm;
    if (proof.algorithm === 'ed25519' && publicKey.asymmetricKeyType === 'ed25519') {
      options = publicKey; algorithm = null;
    } else if (proof.algorithm === 'ecdsa-p256-sha256' && publicKey.asymmetricKeyType === 'ec' &&
               publicKey.asymmetricKeyDetails?.namedCurve === 'prime256v1') {
      options = {key:publicKey,dsaEncoding:'ieee-p1363'}; algorithm = 'sha256';
    } else throw new Error('Algorithme Quantic ID non reconnu.');
    if (!verify(algorithm, Buffer.from(proof.payload,'utf8'), options, Buffer.from(proof.signature,'base64url'))) {
      throw new Error('Signature Quantic ID invalide.');
    }
    return {siteUserId:proof.keyId, signedAtMs};
  };
}

/**
 * All presence state and authentication challenges live in process memory.
 * It is safe to instantiate once per website process, not on every request.
 */
export function createQuanticSitePresence({
  audience, now = Date.now, ttlMs = DEFAULT_PRESENCE_TTL_MS,
  verifyProof = createQuanticSiteProofVerifier({ audience, now }),
} = {}) {
  requireAudience(audience);
  if (!Number.isInteger(ttlMs) || ttlMs < 1000 || ttlMs > 30_000) {
    throw new Error('Durée de présence Quantic ID invalide.');
  }
  if (typeof verifyProof !== 'function') throw new Error('Vérificateur Quantic ID obligatoire.');

  const challenges = new Map();
  const leases = new Map();

  function sweep() {
    const time = now();
    for (const [nonce, record] of challenges) if (time >= record.expiresAt) challenges.delete(nonce);
    for (const [token, record] of leases) if (time >= record.expiresAt) leases.delete(token);
  }

  function begin({ purpose = 'activate', token } = {}) {
    sweep();
    if (!['activate','renew'].includes(purpose)) throw new Error('Opération de présence invalide.');
    if (purpose === 'renew' && (!token || !leases.has(token))) {
      throw new Error('Session Quantic ID absente.');
    }
    const challenge = randomBytes(32).toString('base64url');
    challenges.set(challenge, {
      purpose,
      token: purpose === 'renew' ? token : null,
      expiresAt: now() + CHALLENGE_TTL_MS,
    });
    return { challenge, audience: requireAudience(audience), expiresAt: new Date(now() + CHALLENGE_TTL_MS).toISOString() };
  }

  function consume(challenge, purpose, token) {
    sweep();
    const record = challenges.get(challenge);
    challenges.delete(challenge); // single use, even on a failed signature
    if (!record || record.purpose !== purpose || record.token !== (token ?? null)) {
      throw new Error('Défi Quantic ID absent ou déjà utilisé.');
    }
  }

  async function authenticate(proof, challenge) {
    const verified = await verifyProof({ proof, challenge, audience: requireAudience(audience) });
    if (!verified || !QID_RE.test(verified.siteUserId) ||
        !Number.isFinite(verified.signedAtMs) ||
        Math.abs(now() - verified.signedAtMs) > MAX_PROOF_AGE_MS) {
      throw new Error('Preuve de présence Quantic ID insuffisante.');
    }
    return verified;
  }

  async function activate({ challenge, proof, displayName = '' }) {
    consume(challenge, 'activate', null);
    const verified = await authenticate(proof, challenge);
    if (typeof displayName !== 'string' || displayName.length > 80) {
      throw new Error('Pseudonyme temporaire invalide.');
    }
    const token = randomBytes(32).toString('base64url');
    const expiresAt = now() + ttlMs;
    leases.set(token, { siteUserId: verified.siteUserId, displayName, expiresAt });
    // Token is a secret bearer capability: NEVER log, persist or put in URLs.
    return { token, expiresAt: new Date(expiresAt).toISOString() };
  }

  async function renew({ token, challenge, proof }) {
    consume(challenge, 'renew', token);
    const previous = leases.get(token);
    if (!previous) throw new Error('Session de présence Quantic ID expirée.');
    const verified = await authenticate(proof, challenge);
    if (verified.siteUserId !== previous.siteUserId) {
      throw new Error('Changement d’identité Quantic ID interdit.');
    }
    previous.expiresAt = now() + ttlMs;
    return { expiresAt: new Date(previous.expiresAt).toISOString() };
  }

  function lock(token) {
    sweep();
    const current = leases.get(token);
    if (!current) return false;
    // Lock is an explicit request for disappearance on this site. All active
    // sessions for that Quantic ID on this site disappear, not just one tab.
    for (const [leaseToken, record] of leases) {
      if (record.siteUserId === current.siteUserId) leases.delete(leaseToken);
    }
    for (const [nonce, record] of challenges) {
      if (record.token && !leases.has(record.token)) challenges.delete(nonce);
    }
    return true;
  }

  function listVisible() {
    sweep();
    const unique = new Map();
    for (const {siteUserId,displayName} of leases.values()) {
      unique.set(siteUserId, {siteUserId,displayName,online:true});
    }
    return [...unique.values()];
  }

  function clear() { leases.clear(); challenges.clear(); }

  return {begin,activate,renew,lock,listVisible,sweep,clear};
}
