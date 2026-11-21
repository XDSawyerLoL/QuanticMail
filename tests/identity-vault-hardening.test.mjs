import test from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { consumeRateLimit } from "../lib/security/rate-limit.ts";
import { hasTrustedOrigin } from "../lib/security/origin.ts";
const { navigationTarget, MAIL_ORIGIN, PORTAL_ORIGIN } = createRequire(import.meta.url)("../desktop/navigation-policy.cjs");
test("desktop requires exact HTTPS origins", () => {
  assert.equal(navigationTarget(MAIL_ORIGIN+"/mail"),"mail");
  assert.equal(navigationTarget(PORTAL_ORIGIN+"/"),"portal");
  for (const url of [PORTAL_ORIGIN+".example.com", PORTAL_ORIGIN+"@example.com", MAIL_ORIGIN+":8443", MAIL_ORIGIN.replace("https:","http:"), "file:///tmp/a", "javascript:void(0)", "https://user@quanticmail.onrender.com", "https://example.com"]) assert.equal(navigationTarget(url),"deny");
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
