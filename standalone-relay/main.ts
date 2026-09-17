import { resolve } from "node:path";

import { parseRelayBootstrap } from "./discovery-bootstrap.ts";
import { startRelayServer } from "./server.ts";

export function parseRelayPort(value: string) {
  const port = Number(value);
  if (!Number.isInteger(port) || port < 1 || port > 65_535) {
    throw new Error("QUANTIC_RELAY_PORT doit être un entier entre 1 et 65535.");
  }
  return port;
}

async function main() {
  const host = process.env.QUANTIC_RELAY_HOST ?? "127.0.0.1";
  const port = parseRelayPort(process.env.QUANTIC_RELAY_PORT ?? "8787");
  const dataDir = process.env.QUANTIC_RELAY_DATA_DIR ?? "./data";
  const bootstrapEndpoints = parseRelayBootstrap(process.env.QUANTIC_RELAY_BOOTSTRAP);
  const relay = await startRelayServer({ host, port, dataDir, bootstrapEndpoints });

  console.log(`Quantic Relay V1 écoute sur ${relay.url} — données: ${resolve(dataDir)}`);

  let shutdown: Promise<void> | null = null;
  const beginShutdown = () => {
    if (!shutdown) {
      shutdown = relay.close().catch((error: unknown) => {
        console.error("Échec de l'arrêt propre de Quantic Relay.", error);
        process.exitCode = 1;
      });
    }
    return shutdown;
  };

  process.once("SIGINT", () => {
    void beginShutdown();
  });
  process.once("SIGTERM", () => {
    void beginShutdown();
  });
}

main().catch((error: unknown) => {
  console.error("Impossible de démarrer Quantic Relay.", error);
  process.exitCode = 1;
});
