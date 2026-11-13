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

  // Covers exactly the legacy root-device mismatch seen when users send
  // from Windows 1.3.5. This test uses disposable keys and a test relay.
  await smokeDeviceAuthentication(`http://127.0.0.1:${MAIL_PORT}`);

  console.log("OK : interface locale, relais local, migration et envoi authentifié vérifiés.");
} finally {
  if (server) await new Promise((resolve) => server.close(resolve));
  child.kill();
  rmSync(relayData, { recursive: true, force: true });
}
