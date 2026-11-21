import { createECDH, createCipheriv, hkdfSync, randomBytes, timingSafeEqual, createHash } from 'node:crypto';
import { prepareNativeEnrollment } from './native-enrollment.mjs';

// Lab only. A trusted controller holds the challenge plaintext. No live caller.
// Require possession of both candidate keys before accepting a signed manifest.
export function prepareDualEnrollment(options) {
  const base = prepareNativeEnrollment(options);
  const pub = Buffer.concat([Buffer.from([4]), Buffer.from(options.encryptionKey.x, 'base64url'), Buffer.from(options.encryptionKey.y, 'base64url')]);
  const ephemeral = createECDH('prime256v1');
  const ep = ephemeral.generateKeys();
  const secret = ephemeral.computeSecret(pub);
  const context = Buffer.concat([Buffer.from('quantic-vault-isolated-lab/v1/message\0'), ep, pub]);
  const key = Buffer.from(hkdfSync('sha256', secret, Buffer.alloc(32), context, 32));
  secret.fill(0);
  const nonce = randomBytes(12);
  const evidence = Buffer.concat([createHash('sha256').update(base.challenge).digest(), randomBytes(32)]);
  const expected = createHash('sha256').update(evidence).digest();
  const cipher = createCipheriv('aes-256-gcm', key, nonce);
  cipher.setAAD(context);
  const ciphertext = Buffer.concat([cipher.update(evidence), cipher.final(), cipher.getAuthTag()]);
  key.fill(0); evidence.fill(0);
  let used = false;
  return {
    challenge: base.challenge, deviceId: base.deviceId,
    packet: Object.freeze({ephemeral: ep.toString('base64url'), nonce: nonce.toString('base64url'), ciphertext: ciphertext.toString('base64url')}),
    authorize(signature, recovered, approved) {
      if (used) throw Error('dual enrollment already used');
      // Single attempt; invalid proof cannot turn this into an unlimited oracle.
      used = true;
      if (typeof recovered !== 'string' || !/^[A-Za-z0-9_-]{86}$/.test(recovered)) throw Error('encryption proof required');
      const raw = Buffer.from(recovered, 'base64url');
      const match = raw.length === 64 && raw.toString('base64url') === recovered && timingSafeEqual(createHash('sha256').update(raw).digest(), expected);
      raw.fill(0); expected.fill(0);
      if (!match) throw Error('invalid encryption proof');
      return base.authorize(signature, approved);
    },
    confirm(manifest) { return base.confirm(manifest); }
  };
}
