import test from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { resolve } from "node:path";

const require = createRequire(import.meta.url);
const { resolveStaticPath, LOCAL_MAIL_URL, approvedHost, approvedOrigin } = require("../desktop/local-server.cjs");
const { isMailUrl } = require("../desktop/navigation.cjs");

test("l'app locale ne dépend ni de Hostinger ni de Render", () => {
  assert.equal(LOCAL_MAIL_URL, "http://127.0.0.1:18787/mail/");
  assert.equal(isMailUrl(LOCAL_MAIL_URL), true);
  assert.equal(isMailUrl("https://mediumorchid-badger-314305.hostingersite.com/mail/"), false);
});

test("le serveur local refuse les chemins hors de son répertoire", () => {
  const root = resolve("/fake/quantic");
  assert.equal(resolveStaticPath(root, "/mail/"), resolve(root, "index.html"));
  assert.equal(resolveStaticPath(root, "/mail/vault/"), resolve(root, "vault/index.html"));
  assert.equal(resolveStaticPath(root, "/mail/../private"), null);
  assert.equal(resolveStaticPath(root, "/mail/%2e%2e/%2e%2e/private"), null);
  assert.equal(resolveStaticPath(root, "/api/quantic/health"), null);
});


test("le serveur Windows autorise les deux formes de boucle locale à son port exact", () => {
  assert.equal(approvedHost("127.0.0.1:18787", 18787), true);
  assert.equal(approvedHost("localhost:18787", 18787), true);
  assert.equal(approvedHost("LOCALHOST:18787", 18787), true);
  assert.equal(approvedHost("127.0.0.1:18788", 18787), false);
  assert.equal(approvedHost("attacker.localhost:18787", 18787), false);
  assert.equal(approvedHost("quanticmail.example:18787", 18787), false);
});

test("l'origine HTTP doit correspondre exactement à l'hôte et au port local", () => {
  assert.equal(approvedOrigin(undefined, "127.0.0.1:18787"), true);
  assert.equal(approvedOrigin("http://127.0.0.1:18787", "127.0.0.1:18787"), true);
  assert.equal(approvedOrigin("http://localhost:18787", "localhost:18787"), true);
  assert.equal(approvedOrigin("HTTP://LOCALHOST:18787", "localhost:18787"), true);
  assert.equal(approvedOrigin("null", "127.0.0.1:18787"), false);
  assert.equal(approvedOrigin("http://localhost:18787", "127.0.0.1:18787"), false);
  assert.equal(approvedOrigin("https://127.0.0.1:18787", "127.0.0.1:18787"), false);
  assert.equal(approvedOrigin("http://evil.example:18787", "127.0.0.1:18787"), false);
});
