import test from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const { MAIL_URL, isMailUrl, isSafeExternal } = require("../desktop/navigation.cjs");

test("l'installateur ouvre la version Hostinger testée", () => {
  assert.equal(MAIL_URL, "https://mediumorchid-badger-314305.hostingersite.com/mail/");
  assert.equal(isMailUrl(MAIL_URL), true);
  assert.equal(isMailUrl(MAIL_URL + "vault/"), true);
  assert.equal(isMailUrl(MAIL_URL + "network/?tab=relays"), true);
});

test("la navigation intégrée ne sort pas de /mail", () => {
  assert.equal(isMailUrl("https://mediumorchid-badger-314305.hostingersite.com/"), false);
  assert.equal(isMailUrl("https://mediumorchid-badger-314305.hostingersite.com/mailicious"), false);
  assert.equal(isMailUrl("http://mediumorchid-badger-314305.hostingersite.com/mail/"), false);
  assert.equal(isMailUrl("https://mediumorchid-badger-314305.hostingersite.com.evil.test/mail/"), false);
  assert.equal(isMailUrl("https://someone@mediumorchid-badger-314305.hostingersite.com/mail/"), false);
  assert.equal(isMailUrl("javascript:alert(1)"), false);
});

test("le navigateur système n'ouvre que des URL externes autorisées", () => {
  assert.equal(isSafeExternal("https://quanticmail.onrender.com"), true);
  assert.equal(isSafeExternal("mailto:contact@example.com"), true);
  assert.equal(isSafeExternal("file:///C:/Windows/system.ini"), false);
  assert.equal(isSafeExternal("javascript:alert(1)"), false);
  assert.equal(isSafeExternal("http://insecure.example.com"), false);
  assert.equal(isSafeExternal("https://someone@example.com"), false);
});
