import assert from "node:assert/strict";
import test from "node:test";

import {
  canonicalPqcDeviceProposalText,
  detectBrowserPqcCapabilities,
  generateLocalPqcKeyMaterial,
  publicPqcDeviceProposal,
  verifyPqcDeviceProposal,
} from "../lib/quantic/device-pqc.ts";

const capabilities = await detectBrowserPqcCapabilities();
const skip = capabilities.available ? false : `WebCrypto PQ unavailable in ${capabilities.runtime}`;

test("browser PQ runtime creates local ML-KEM and ML-DSA private material", { skip }, async () => {
  const material = await generateLocalPqcKeyMaterial();
  assert.ok(material);
  assert.equal(material.version, 1);
  assert.match(material.mlKemPublicKeySpki, /^[A-Za-z0-9_-]+$/);
  assert.match(material.mlKemPrivateKeyPkcs8, /^[A-Za-z0-9_-]+$/);
  assert.match(material.mlDsaPublicKeySpki, /^[A-Za-z0-9_-]+$/);
  assert.match(material.mlDsaPrivateKeyPkcs8, /^[A-Za-z0-9_-]+$/);
  assert.notEqual(material.mlKemPublicKeySpki, material.mlKemPrivateKeyPkcs8);
  assert.notEqual(material.mlDsaPublicKeySpki, material.mlDsaPrivateKeyPkcs8);
});

test("public PQ device proposal never exposes private PQ material", { skip }, async () => {
  const material = await generateLocalPqcKeyMaterial();
  assert.ok(material);
  const context = {
    canonicalAddress: `alice~${"a".repeat(32)}@quantic`,
    deviceId: "d-0123456789",
    createdAt: "2026-09-17T08:30:00.000Z",
  };
  const proposal = await publicPqcDeviceProposal(material, context);
  const serialized = JSON.stringify(proposal);

  assert.equal(serialized.includes("Private"), false);
  assert.equal(serialized.includes("Pkcs8"), false);
  assert.equal(serialized.includes(material.mlKemPrivateKeyPkcs8), false);
  assert.equal(serialized.includes(material.mlDsaPrivateKeyPkcs8), false);
  assert.equal(proposal.mlKemPublicKeySpki, material.mlKemPublicKeySpki);
  assert.equal(proposal.mlDsaPublicKeySpki, material.mlDsaPublicKeySpki);
  assert.equal(await verifyPqcDeviceProposal(proposal, context), true);

  const tampered = { ...proposal, mlKemPublicKeySpki: `${proposal.mlKemPublicKeySpki.slice(0, -1)}A` };
  assert.equal(await verifyPqcDeviceProposal(tampered, context), false);
});

test("PQ device proposal canonical text binds identity, device and both public keys", { skip }, async () => {
  const material = await generateLocalPqcKeyMaterial();
  assert.ok(material);
  const context = {
    canonicalAddress: `alice~${"b".repeat(32)}@quantic`,
    deviceId: "d-abcdef0123",
    createdAt: "2026-09-17T08:31:00.000Z",
  };
  const proposal = await publicPqcDeviceProposal(material, context);
  const text = canonicalPqcDeviceProposalText(proposal, context);
  assert.match(text, /quantic-device-pqc-proposal-v1/);
  assert.match(text, /d-abcdef0123/);
  assert.match(text, /ML-KEM-768/);
  assert.match(text, /ML-DSA-65/);
});
