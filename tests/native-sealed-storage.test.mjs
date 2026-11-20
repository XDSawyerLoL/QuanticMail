import test from "node:test";
import assert from "node:assert/strict";
import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import {
  NATIVE_SEALED_FORMAT, isNativeSealedRecord, sealNativeRecord, unsealNativeRecord,
} from "../lib/quantic/native-sealed-storage.mjs";

const key = randomBytes(32);
const fakePlatformBridge = {
  async seal(text) {
    const iv = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", key, iv);
    const body = Buffer.concat([cipher.update(text, "utf8"), cipher.final()]);
    return Buffer.concat([iv, cipher.getAuthTag(), body]).toString("base64");
  },
  async unseal(ciphertext) {
    const data = Buffer.from(ciphertext, "base64");
    const decipher = createDecipheriv("aes-256-gcm", key, data.subarray(0,12));
    decipher.setAuthTag(data.subarray(12,28));
    return Buffer.concat([decipher.update(data.subarray(28)), decipher.final()]).toString("utf8");
  },
};

test("Windows records contain no clear private key or authorization token", async () => {
  const clear = { privateKey: { kty: "EC", d: "secret-private-component" }, authToken: "secret-token" };
  const sealed = await sealNativeRecord(clear, fakePlatformBridge);
  assert.equal(sealed.format, NATIVE_SEALED_FORMAT);
  assert.equal(isNativeSealedRecord(sealed), true);
  assert.equal(JSON.stringify(sealed).includes("secret-private-component"), false);
  assert.equal(JSON.stringify(sealed).includes("secret-token"), false);
  assert.deepEqual(await unsealNativeRecord(sealed, fakePlatformBridge), clear);
});
test("Windows encrypted records cannot be read without the platform bridge or correct key", async () => {
  const sealed = await sealNativeRecord({ privateKey: "private" }, fakePlatformBridge);
  await assert.rejects(unsealNativeRecord(sealed, null), /nécessite le coffre Windows/);
  await assert.rejects(unsealNativeRecord({ ...sealed, ciphertext: Buffer.alloc(60).toString("base64") }, fakePlatformBridge));
});
test("legacy records can be read for authenticated in-place migration", async () => {
  const legacy = { privateKey: { d: "old" } };
  assert.equal(await unsealNativeRecord(legacy, fakePlatformBridge), legacy);
  assert.equal(await sealNativeRecord(legacy, null), legacy);
});
test("rejects malformed encrypted envelopes instead of silently downgrading", async () => {
  await assert.rejects(unsealNativeRecord({ format: NATIVE_SEALED_FORMAT, version: 9 }, fakePlatformBridge), /non reconnue/);
});
test("native bridge requires same-origin top-level Windows renderer and fails closed", () => {
  const main = readFileSync(new URL("../desktop/main.cjs", import.meta.url), "utf8");
  const preload = readFileSync(new URL("../desktop/preload.cjs", import.meta.url), "utf8");
  const localDb = readFileSync(new URL("../lib/quantic/local-db.ts", import.meta.url), "utf8");
  assert.match(main, /safeStorage\.encryptString/);
  assert.match(main, /safeStorage\.decryptString/);
  assert.match(main, /event\.senderFrame !== mainWindow\.webContents\.mainFrame/);
  assert.match(main, /preload: join\(__dirname, "preload\.cjs"\)/);
  assert.match(preload, /contextBridge\.exposeInMainWorld/);
  assert.match(localDb, /NEXT_PUBLIC_QUANTIC_DESKTOP/);
  assert.match(localDb, /migrateLegacyRecord/);
  assert.match(localDb, /protectRecord\(next\)/);
  assert.match(localDb, /protectRecord\(device\)/);
});
