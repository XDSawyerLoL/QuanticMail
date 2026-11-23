import test from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { consumeRateLimit } from "../lib/security/rate-limit.ts";
import { hasTrustedOrigin } from "../lib/security/origin.ts";
const { navigationTarget, MAIL_ORIGIN, PORTAL_ORIGIN } = createRequire(import.meta.url)("../desktop/navigation-policy.cjs");
test("retired desktop navigation denies all Web origins, including formerly trusted sites", () => {
  // Native-only policy deliberately removed remote renderer destinations.
  // Old checks for allowed Mail/Portal origins must not reopen this boundary.
  assert.equal(MAIL_ORIGIN,null);
  assert.equal(PORTAL_ORIGIN,null);
  for (const url of [
    "https://quanticmail.onrender.com/mail",
    "https://mediumorchid-badger-314305.hostingersite.com/",
    "https://quanticmail.onrender.com.evil.example/",
    "https://quanticmail.onrender.com@evil.example/",
    "https://quanticmail.onrender.com:8443/mail",
    "http://quanticmail.onrender.com/mail",
    "https://user@quanticmail.onrender.com",
    "file:///tmp/a","javascript:void(0)","https://example.com",
    null,undefined,""
  ]) assert.equal(navigationTarget(url),"deny");
});
test("origin comparison does not trust same host with different scheme or origin suffix", () => {
  const r = (value) => ({headers:new Headers({origin:value}),nextUrl:new URL("https://quanticmail.onrender.com")});
  assert.equal(hasTrustedOrigin(r("https://quanticmail.onrender.com")),true);
  assert.equal(hasTrustedOrigin(r("http://quanticmail.onrender.com")),false);
  assert.equal(hasTrustedOrigin(r("https://quanticmail.onrender.com.evil.example")),false);
  assert.equal(hasTrustedOrigin(r("https://quanticmail.onrender.com/path")),false);
});
test("local guard enforces limits and rejects malformed input", () => {
  const k="test-"+crypto.randomUUID();
  assert.equal(consumeRateLimit(k,2).ok,true);
  assert.equal(consumeRateLimit(k,2).ok,true);
  assert.equal(consumeRateLimit(k,2).ok,false);
  assert.equal(consumeRateLimit("x".repeat(513)).ok,false);
  assert.equal(consumeRateLimit(k,0).ok,false);
  assert.equal(consumeRateLimit(k,1,Infinity).ok,false);
});
