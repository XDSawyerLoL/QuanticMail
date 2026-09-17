import assert from "node:assert/strict";
import test from "node:test";

import { loadRegistryManifestsByHandle } from "../lib/quantic/registry-store.ts";

const previous = {
  token: process.env.QUANTIC_GITHUB_TOKEN,
  owner: process.env.QUANTIC_GITHUB_OWNER,
  repo: process.env.QUANTIC_GITHUB_REPO,
  branch: process.env.QUANTIC_GITHUB_BRANCH,
};

function manifest(handle: string, fingerprint: string) {
  return {
    format: "quantic-identity-manifest",
    version: 1,
    payload: {
      version: 1,
      sequence: 1,
      canonicalAddress: `${handle}~${fingerprint}@quantic`,
      handle,
      fingerprint,
      identityPublicKey: { kty: "EC", crv: "P-256", x: "enc-x", y: "enc-y" },
      identitySigningPublicKey: { kty: "EC", crv: "P-256", x: "sig-x", y: "sig-y" },
      devices: [],
      revocations: [],
      issuedAt: "2026-09-17T12:00:00.000Z",
    },
    signature: "test-signature",
  };
}

function jsonResponse(value: unknown, status = 200) {
  return new Response(JSON.stringify(value), {
    status,
    headers: { "content-type": "application/json" },
  });
}

test.afterEach(() => {
  process.env.QUANTIC_GITHUB_TOKEN = previous.token;
  process.env.QUANTIC_GITHUB_OWNER = previous.owner;
  process.env.QUANTIC_GITHUB_REPO = previous.repo;
  process.env.QUANTIC_GITHUB_BRANCH = previous.branch;
});

test("finds a durable identity by short @quantic handle after live relay state is gone", async () => {
  process.env.QUANTIC_GITHUB_TOKEN = "test-token";
  process.env.QUANTIC_GITHUB_OWNER = "XDSawyerLoL";
  process.env.QUANTIC_GITHUB_REPO = "QuanticMail";
  process.env.QUANTIC_GITHUB_BRANCH = "registry";

  const benoit = manifest("benoit.v3", "0123456789abcdef0123456789abcdef");
  const alice = manifest("alice", "fedcba9876543210fedcba9876543210");
  const files = [
    { name: "a.json", path: "registry/identities/a.json", type: "file" },
    { name: "b.json", path: "registry/identities/b.json", type: "file" },
  ];

  const previousFetch = globalThis.fetch;
  globalThis.fetch = (async (input: string | URL | Request) => {
    const url = String(input);
    if (url.includes("/contents/registry/identities?ref=")) return jsonResponse(files);
    if (url.includes("/contents/registry/identities/a.json?ref=")) {
      return jsonResponse({ content: Buffer.from(JSON.stringify(benoit)).toString("base64"), encoding: "base64" });
    }
    if (url.includes("/contents/registry/identities/b.json?ref=")) {
      return jsonResponse({ content: Buffer.from(JSON.stringify(alice)).toString("base64"), encoding: "base64" });
    }
    return jsonResponse({ message: "not found" }, 404);
  }) as typeof fetch;

  try {
    const matches = await loadRegistryManifestsByHandle("benoit.v3@quantic");
    assert.equal(matches.length, 1);
    assert.equal(matches[0]?.payload.canonicalAddress, "benoit.v3~0123456789abcdef0123456789abcdef@quantic");
  } finally {
    globalThis.fetch = previousFetch;
  }
});

test("keeps same-handle identities ambiguous instead of choosing one silently", async () => {
  process.env.QUANTIC_GITHUB_TOKEN = "test-token";
  process.env.QUANTIC_GITHUB_BRANCH = "registry";

  const first = manifest("benoit.v3", "0123456789abcdef0123456789abcdef");
  const second = manifest("benoit.v3", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
  const files = [
    { name: "a.json", path: "registry/identities/a.json", type: "file" },
    { name: "b.json", path: "registry/identities/b.json", type: "file" },
  ];

  const previousFetch = globalThis.fetch;
  globalThis.fetch = (async (input: string | URL | Request) => {
    const url = String(input);
    if (url.includes("/contents/registry/identities?ref=")) return jsonResponse(files);
    if (url.includes("/contents/registry/identities/a.json?ref=")) {
      return jsonResponse({ content: Buffer.from(JSON.stringify(first)).toString("base64"), encoding: "base64" });
    }
    if (url.includes("/contents/registry/identities/b.json?ref=")) {
      return jsonResponse({ content: Buffer.from(JSON.stringify(second)).toString("base64"), encoding: "base64" });
    }
    return jsonResponse({ message: "not found" }, 404);
  }) as typeof fetch;

  try {
    const matches = await loadRegistryManifestsByHandle("benoit.v3@quantic");
    assert.equal(matches.length, 2);
  } finally {
    globalThis.fetch = previousFetch;
  }
});
