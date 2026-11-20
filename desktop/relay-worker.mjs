import { startRelayServer } from "../standalone-relay/server.ts";
import { parseRelayBootstrap } from "../standalone-relay/discovery-bootstrap.ts";

const parent = process.parentPort;
const dataDir = process.env.QUANTIC_RELAY_DATA_DIR;
let relay;

async function main() {
  if (!dataDir) throw new Error("Dossier de données de relais absent.");
  // Never start an unauthenticated desktop relay, even if called outside Electron.
  const accessToken = process.env.QUANTIC_DESKTOP_RELAY_TOKEN;
  if (!accessToken || !/^[0-9a-f]{64}$/.test(accessToken)) {
    throw new Error("Jeton de session du relais Windows absent ou invalide.");
  }
  relay = await startRelayServer({
    host: "127.0.0.1",
    port: Number(process.env.QUANTIC_LOCAL_RELAY_PORT || 18788),
    dataDir,
    localAccessToken: accessToken,
    bootstrapEndpoints: parseRelayBootstrap(process.env.QUANTIC_RELAY_BOOTSTRAP || "")
  });
  parent?.postMessage({ type: "ready", port: relay.port, relayId: relay.relayId });
}

parent?.on("message", async ({ data }) => {
  if (data?.type !== "shutdown") return;
  try {
    await relay?.close();
  } finally {
    process.exit(0);
  }
});

void main().catch((error) => {
  parent?.postMessage({ type: "error", message: error instanceof Error ? error.message : String(error) });
  console.error("Impossible de lancer le relais Quantic local :", error);
  process.exitCode = 1;
});
