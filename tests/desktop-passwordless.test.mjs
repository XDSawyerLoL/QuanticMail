import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const onboarding = readFileSync(new URL("../components/quantic-network-v11-app.tsx", import.meta.url), "utf8");
const vault = readFileSync(new URL("../components/identity-vault-app.tsx", import.meta.url), "utf8");
const filePairing = readFileSync(new URL("../components/devices-v1-app.tsx", import.meta.url), "utf8");

test("Windows launches the signed, passwordless device pairing as its primary onboarding", () => {
  const desktopStart = onboarding.indexOf('process.env.NEXT_PUBLIC_QUANTIC_DESKTOP === "true" ?');
  const signedPairing = onboarding.indexOf('href="/devices/files"', desktopStart);
  const optionalVault = onboarding.indexOf('href="/vault"', desktopStart);
  assert.ok(desktopStart >= 0);
  assert.ok(signedPairing > desktopStart);
  assert.ok(optionalVault > signedPairing);
  assert.match(onboarding, /Associer ce PC sans mot de passe/);
});

test("vault password is labeled optional and is not the Quantic account password", () => {
  assert.match(vault, /RESTAURATION D.UNE SAUVEGARDE \(FACULTATIF\)/);
  assert.match(vault, /Il ne s'agit pas d'un mot de passe Quantic Mail/);
  assert.match(vault, /Associer mon PC par certificat signé/);
});

test("existing signed-file pairing works without a vault password", () => {
  assert.match(filePairing, /createPendingDevice/);
  assert.match(filePairing, /createDeviceCertificate/);
  assert.match(filePairing, /installDeviceCertificate/);
  assert.match(filePairing, /\.quantic-device-request/);
  assert.match(filePairing, /\.quantic-device-cert/);
  assert.doesNotMatch(filePairing, /importIdentityVault|exportIdentityVault/);
});
