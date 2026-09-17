import assert from "node:assert/strict";
import test from "node:test";

import {
  detectPqcCapabilities,
  generateMlDsa65KeyPair,
  generateMlKem768KeyPair,
  mlDsaSign,
  mlDsaVerify,
  mlKemDecapsulate,
  mlKemEncapsulate,
} from "../lib/quantic/pqc-runtime-node.ts";

const capabilities = detectPqcCapabilities();

const pqSkip = capabilities.mlKem768 && capabilities.mlDsa65
  ? false
  : `runtime ${capabilities.runtime} lacks native ML-KEM-768/ML-DSA-65`;

test("native ML-KEM-768 encapsulation round-trips the shared secret", { skip: pqSkip }, () => {
  const pair = generateMlKem768KeyPair();
  const encapsulated = mlKemEncapsulate(pair.publicKeySpki);
  const recovered = mlKemDecapsulate(pair.privateKeyPkcs8, encapsulated.ciphertext);

  assert.equal(encapsulated.sharedSecret.length, 32);
  assert.deepEqual(recovered, encapsulated.sharedSecret);
  assert.match(pair.publicKeySpki, /^[A-Za-z0-9_-]+$/);
  assert.match(pair.privateKeyPkcs8, /^[A-Za-z0-9_-]+$/);
});

test("native ML-DSA-65 signs and rejects tampered data", { skip: pqSkip }, () => {
  const pair = generateMlDsa65KeyPair();
  const message = Buffer.from("Quantic Crypto V2 runtime proof", "utf8");
  const signature = mlDsaSign(pair.privateKeyPkcs8, message);

  assert.equal(mlDsaVerify(pair.publicKeySpki, message, signature), true);
  assert.equal(
    mlDsaVerify(pair.publicKeySpki, Buffer.from("Quantic Crypto V2 tampered", "utf8"), signature),
    false,
  );
});
