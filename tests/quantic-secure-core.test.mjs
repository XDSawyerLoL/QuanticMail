import assert from 'node:assert/strict';
import test from 'node:test';
import { webcrypto } from 'node:crypto';
import { FORMAT, importVolatileRootKey, sealRecord, unsealRecord } from '../lib/quantic-core/quantic-secure-core.mjs';
const random = () => webcrypto.getRandomValues(new Uint8Array(32));
const scope = { identityId: 'qid_a1b2', namespace: 'quantic-mail', recordId: 'device-main' };
const enc = new TextEncoder();
const dec = new TextDecoder();

async function root() { return importVolatileRootKey(random(), webcrypto); }

test('QSC1 stores an opaque binary record without JSON or private key plaintext', async () => {
  const rootKey = await root();
  const privateJwk = '{"privateKey":{"d":"secret-jwk"}}';
  const file = await sealRecord({ rootKey, ...scope, plaintext: enc.encode(privateJwk), cryptoImpl: webcrypto });
  assert.ok(file instanceof Uint8Array);
  assert.equal(dec.decode(file.subarray(0,4)), FORMAT);
  assert.equal(dec.decode(file).includes('secret-jwk'), false);
  assert.equal(dec.decode(file).includes('privateKey'), false);
  assert.equal(dec.decode(await unsealRecord({ rootKey, ...scope, file, cryptoImpl: webcrypto })), privateJwk);
  await assert.rejects(webcrypto.subtle.exportKey('raw', rootKey));
});

test('QSC1 refuses an unrelated Quantic ID, namespace or record', async () => {
  const rootKey = await root();
  const file = await sealRecord({ rootKey, ...scope, plaintext: enc.encode('key'), cryptoImpl: webcrypto });
  for (const wrong of [{ identityId: 'qid_other' }, { namespace: 'quantic-network' }, { recordId: 'device-other' }]) {
    await assert.rejects(unsealRecord({ rootKey, ...scope, ...wrong, file, cryptoImpl: webcrypto }), /intégrité invalide/);
  }
});

test('QSC1 rejects wrong root key, tampering and malformed header', async () => {
  const rootKey = await root();
  const file = await sealRecord({ rootKey, ...scope, plaintext: enc.encode('secret'), cryptoImpl: webcrypto });
  await assert.rejects(unsealRecord({ rootKey: await root(), ...scope, file, cryptoImpl: webcrypto }));
  const tampered = file.slice(); tampered[tampered.length-1] ^= 1;
  await assert.rejects(unsealRecord({ rootKey, ...scope, file: tampered, cryptoImpl: webcrypto }));
  const corruptHeader = file.slice(); corruptHeader[36] ^= 1;
  await assert.rejects(unsealRecord({ rootKey, ...scope, file: corruptHeader, cryptoImpl: webcrypto }), /Longueur/);
  const badMagic = file.slice(); badMagic[0] = 0;
  await assert.rejects(unsealRecord({ rootKey, ...scope, file: badMagic, cryptoImpl: webcrypto }), /Format/);
});

test('QSC1 uses independent nonces and HKDF salts per encryption', async () => {
  const rootKey = await root(), plaintext = enc.encode('repeat');
  const a = await sealRecord({ rootKey, ...scope, plaintext, cryptoImpl: webcrypto });
  const b = await sealRecord({ rootKey, ...scope, plaintext, cryptoImpl: webcrypto });
  assert.notDeepEqual(a, b);
  assert.notDeepEqual(a.subarray(8,24), b.subarray(8,24));
  assert.notDeepEqual(a.subarray(24,36), b.subarray(24,36));
});

test('QSC1 fails closed on missing key and missing secure unlock secret', async () => {
  await assert.rejects(importVolatileRootKey(new Uint8Array(12), webcrypto), /256 bits/);
  await assert.rejects(sealRecord({ rootKey: undefined, ...scope, plaintext: enc.encode('key'), cryptoImpl: webcrypto }), /non exportable/);
  await assert.rejects(sealRecord({ rootKey: await root(), ...scope, plaintext: enc.encode('key'), recordId: '../../bad', cryptoImpl: webcrypto }), /Contexte/);
});
