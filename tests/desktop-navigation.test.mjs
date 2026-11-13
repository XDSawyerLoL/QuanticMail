import test from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";
const require = createRequire(import.meta.url);
const { MAIL_URL, isMailUrl, isSafeExternal } = require("../desktop/navigation.cjs");

test("la fenêtre Electron ne pointe que vers l'application installée localement", () => {
  assert.equal(MAIL_URL, "http://127.0.0.1:18787/mail/");
  assert.equal(isMailUrl(MAIL_URL), true);
  assert.equal(isMailUrl(MAIL_URL + "vault/"), true);
  assert.equal(isMailUrl(MAIL_URL + "network/?tab=relays"), true);
  assert.equal(isMailUrl("https://mediumorchid-badger-314305.hostingersite.com/mail/"), false);
});

test("la navigation ne sort pas de l'interface locale", () => {
  assert.equal(isMailUrl("http://127.0.0.1:18787/"), false);
  assert.equal(isMailUrl("http://127.0.0.1:18787/mailicious"), false);
  assert.equal(isMailUrl("http://evil.example.test/mail/"), false);
  assert.equal(isMailUrl("http://127.0.0.1:18788/mail/"), false);
  assert.equal(isMailUrl("file:///C:/etc/passwd"), false);
});

test("les liens externes ne permettent pas les protocoles dangereux", () => {
  assert.equal(isSafeExternal("https://quanticmail.onrender.com"), true);
  assert.equal(isSafeExternal("mailto:contact@example.com"), true);
  assert.equal(isSafeExternal("file:///C:/Windows/system.ini"), false);
  assert.equal(isSafeExternal("javascript:alert(1)"), false);
  assert.equal(isSafeExternal("http://example.com"), false);
  assert.equal(isSafeExternal("https://someone@example.com"), false);
});
