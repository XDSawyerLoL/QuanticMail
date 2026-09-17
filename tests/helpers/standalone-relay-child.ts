import { startRelayServer } from "../../standalone-relay/server.ts";

const dataDir = process.env.QUANTIC_TEST_RELAY_DATA_DIR;
if (!dataDir) throw new Error("QUANTIC_TEST_RELAY_DATA_DIR requis.");

const requestedPort = Number(process.env.QUANTIC_TEST_RELAY_PORT ?? "0");
if (!Number.isInteger(requestedPort) || requestedPort < 0 || requestedPort > 65_535) {
  throw new Error("QUANTIC_TEST_RELAY_PORT invalide.");
}

const relay = await startRelayServer({
  host: "127.0.0.1",
  port: requestedPort,
  dataDir,
});

process.send?.({
  type: "ready",
  url: relay.url,
  relayId: relay.relayId,
});

let shuttingDown = false;
async function shutdown() {
  if (shuttingDown) return;
  shuttingDown = true;
  await relay.close();
  process.send?.({ type: "closed" });
  process.disconnect?.();
}

process.on("message", (message) => {
  if (message && typeof message === "object" && (message as { type?: string }).type === "shutdown") {
    void shutdown().catch((error) => {
      console.error(error);
      process.exitCode = 1;
      process.disconnect?.();
    });
  }
});

process.once("SIGTERM", () => {
  void shutdown().finally(() => process.exit());
});

process.once("SIGINT", () => {
  void shutdown().finally(() => process.exit());
});
