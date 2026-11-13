import { spawn } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { createRequire } from "node:module";
import { smokeDeviceAuthentication } from "./desktop-auth-smoke.mjs";

const require = createRequire(import.meta.url);
const { startLocalServer, MAIL_PORT, RELAY_PORT } = require("../desktop/local-server.cjs");
const relayPath = resolve("desktop/bundle/relay-worker.cjs");
const staticRoot = resolve("desktop/bundle/mail");
const relayData = mkdtempSync(join(tmpdir(), "quantic-desktop-smoke-"));

const child = spawn(process.execPath, [relayPath], {
  env: {
    ...process.env,
    QUANTIC_RELAY_DATA_DIR: relayData,
    QUANTIC_LOCAL_RELAY_PORT: String(RELAY_PORT),
    QUANTIC_RELAY_BOOTSTRAP: "",
    AURA_QUANTIC_MAIL_TOKEN: "",
    AURA_IDENTITY_VAULT_TOKEN: ""
  },
  stdio: ["ignore", "pipe", "pipe"],
  windowsHide: true
});
let output = "";
child.stdout.on("data", (data) => { output += data.toString(); });
child.stderr.on("data", (data) => { output += data.toString(); });
let server;

async function healthy(url) {
  const response = await fetch(url);
  if (!response.ok) throw new Error("HTTP " + response.status);
  const data = await response.json();
  if (data.ok !== true || data.protocol !== "quantic-relay/1") throw new Error("Relais Quantic invalide");
  return data;
}

try {
  let ready = false;
  for (let attempt = 0; attempt < 60; attempt++) {
    if (child.exitCode !== null) throw new Error("Le relais local a quitté : " + output);
    try {
      await healthy(`http://127.0.0.1:${RELAY_PORT}/api/quantic/health`);
      ready = true;
      break;
    } catch {
      await delay(300);
    }
  }
  if (!ready) throw new Error("Le relais local ne démarre pas.\n" + output);

  const app = await startLocalServer({ staticRoot, port: MAIL_PORT, relayPort: RELAY_PORT });
  server = app.server;
  const response = await fetch(app.url);
  if (response.status !== 200) throw new Error("Interface locale : HTTP " + response.status);
  const html = await response.text();
  if (!html.includes("<html")) throw new Error("La page HTML locale est invalide.");
  const routed = await healthy(`http://127.0.0.1:${MAIL_PORT}/api/quantic/health`);
  if (!routed.relayId) throw new Error("Identifiant de relais manquant.");

  // Exercise real Chromium-style headers through the Windows gateway,
  // rather than only Node fetch requests which normally omit Origin.
  const localHeaders = {
    origin: `http://127.0.0.1:${MAIL_PORT}`,
    "sec-fetch-site": "same-origin",
  };
  const manifestMissing = await fetch(
    `http://127.0.0.1:${MAIL_PORT}/api/quantic/manifest?handle=smokeauth~aaaaaaaaaa@quantic`,
    { headers: localHeaders },
  );
  if (manifestMissing.status !== 404 || manifestMissing.headers.has("x-quantic-local-guard")) {
    throw new Error(`Le GET manifeste navigateur devrait atteindre le relais (404), reçu HTTP ${manifestMissing.status}.`);
  }
  const postManifest = await fetch(
    `http://127.0.0.1:${MAIL_PORT}/api/quantic/manifest`,
    { method: "POST", headers: { ...localHeaders, "content-type": "application/json" },
      body: JSON.stringify({ manifest: null }) },
  );
  if (postManifest.status !== 400 || postManifest.headers.has("x-quantic-local-guard")) {
    throw new Error(`Le POST manifeste navigateur devrait atteindre le relais (400), reçu HTTP ${postManifest.status}.`);
  }
  const invalidOrigin = await fetch(
    `http://127.0.0.1:${MAIL_PORT}/api/quantic/health`,
    { headers: { origin: "http://evil.example:18787" } },
  );
  if (invalidOrigin.status !== 403 || invalidOrigin.headers.get("x-quantic-local-guard") !== "origin") {
    throw new Error("La protection d'origine locale ne rejette pas correctement un site externe.");
  }
  const invalidBody = await invalidOrigin.json();
  if (!invalidBody.error?.includes("origine")) {
    throw new Error("Le refus d'origine devrait afficher un diagnostic JSON explicite.");
  }
  const hostileFetch = await fetch(
    `http://127.0.0.1:${MAIL_PORT}/api/quantic/health`,
    { headers: { "sec-fetch-site": "cross-site" } },
  );
  if (hostileFetch.status !== 403 || hostileFetch.headers.get("x-quantic-local-guard") !== "crossSite") {
    throw new Error("La protection du serveur local laisse passer une requête cross-site.");
  }

  // Covers exactly the legacy root-device mismatch seen when users send
  // from Windows 1.3.5. This test uses disposable keys and a test relay.
  await smokeDeviceAuthentication(`http://127.0.0.1:${MAIL_PORT}`);

  console.log("OK : interface locale, relais local, migration et envoi authentifié vérifiés.");
} finally {
  if (server) await new Promise((resolve) => server.close(resolve));
  child.kill();
  rmSync(relayData, { recursive: true, force: true });
}
