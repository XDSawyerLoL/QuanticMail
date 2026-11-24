import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { runInNewContext } from "node:vm";
import { generateKeyPairSync } from "node:crypto";
import { createIdentityChallenge } from "../lib/quantic/relay.ts";

test("relay refuses private material in either public JWK field", () => {
  const { publicKey, privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const pub = publicKey.export({ format: "jwk" });
  const priv = privateKey.export({ format: "jwk" });
  assert.throws(() => createIdentityChallenge({ handle: "audit-test", publicKey: priv, signingPublicKey: pub }), /Clé publique/);
  assert.throws(() => createIdentityChallenge({ handle: "audit-test", publicKey: pub, signingPublicKey: priv }), /Clé publique/);
  assert.throws(() => createIdentityChallenge({ handle: "audit-test", publicKey: null, signingPublicKey: pub }), /Clé publique/);
  assert.ok(createIdentityChallenge({ handle: "audit-test", publicKey: pub, signingPublicKey: pub }).challenge);
});

test("desktop rejects cross-origin redirects and protects child windows", () => {
  const external = [];
  const windows = [];
  class BrowserWindow {
    constructor() {
      const handlers = new Map();
      this.webContents = {
        handlers,
        on(name, cb) { handlers.set(name, cb); },
        setWindowOpenHandler(cb) { this.openHandler = cb; },
      };
      windows.push(this);
    }
    loadURL() {}
  }
  const electron = {
    app: { whenReady: () => ({ then: cb => cb() }), on() {}, setAppUserModelId() {} },
    BrowserWindow,
    shell: { openExternal: async url => { external.push(url); } },
  };
  runInNewContext(readFileSync(new URL("../desktop/main.cjs", import.meta.url), "utf8"), {
    require: name => { assert.equal(name, "electron"); return electron; }, URL,
  });
  const verify = win => {
    const redirect = win.webContents.handlers.get("will-redirect");
    let blocked = 0;
    const event = { preventDefault: () => blocked++ };
    redirect(event, "https://quanticmail.onrender.com/mail");
    assert.equal(blocked, 0);
    redirect(event, "https://example.invalid/");
    redirect(event, "https://mediumorchid-badger-314305.hostingersite.com.example.invalid/");
    assert.equal(blocked, 2);
    assert.equal(external.length, 0);
  };
  verify(windows[0]);
  const child = new BrowserWindow();
  windows[0].webContents.handlers.get("did-create-window")(child);
  verify(child);
});
