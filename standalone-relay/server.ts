import { createServer, type Server } from "node:http";

import { bootstrapDiscoveryPeers } from "./discovery-bootstrap.ts";
import { createDiscoveryHandleRequestHandler } from "./discovery-handle-http.ts";
import { createDiscoveryRequestHandler } from "./discovery-http.ts";
import { createDiscoveryResolveRequestHandler } from "./discovery-resolve-http.ts";
import { retryPendingFederationReceipts } from "./federation-retry.ts";
import { createRelayRequestHandler } from "./http.ts";
import { loadOrCreateRelayIdentity } from "./identity.ts";
import { createPostgresRelayPersistenceFromUrl } from "./postgres-storage.ts";
import { createCompatRegisterRequestHandler } from "./register-compat-http.ts";
import { RelayRuntime } from "./runtime.ts";
import { createFileRelayStateStore } from "./storage.ts";

export type RelayServerOptions = {
  host?: string;
  port?: number;
  dataDir?: string;
  databaseUrl?: string;
  publicEndpoint?: string;
  bootstrapEndpoints?: string[];
};

export type RunningRelayServer = {
  host: string;
  port: number;
  url: string;
  dataDir: string;
  relayId: string;
  close(): Promise<void>;
};

function closeHttpServer(server: Server) {
  return new Promise<void>((resolve, reject) => {
    server.close((error) => {
      if (error) reject(error);
      else resolve();
    });
  });
}

function urlHost(host: string) {
  return host.includes(":") && !host.startsWith("[") ? `[${host}]` : host;
}

function validateServerPort(port: number) {
  if (!Number.isInteger(port) || port < 0 || port > 65_535) {
    throw new Error("Port Quantic Relay invalide.");
  }
}

export async function startRelayServer(
  options: RelayServerOptions = {},
): Promise<RunningRelayServer> {
  const host = options.host ?? "127.0.0.1";
  const port = options.port ?? 8787;
  const dataDir = options.dataDir ?? "./data";
  validateServerPort(port);

  const databaseUrl = options.databaseUrl?.trim() || "";
  const postgresPersistence = databaseUrl
    ? await createPostgresRelayPersistenceFromUrl(databaseUrl)
    : null;
  const relayIdentity = postgresPersistence
    ? await postgresPersistence.loadOrCreateIdentity()
    : await loadOrCreateRelayIdentity(dataDir);
  const store = postgresPersistence?.stateStore ?? createFileRelayStateStore(dataDir);
  const runtime = new RelayRuntime(store);
  await runtime.initialize();

  let publicEndpoint = options.publicEndpoint ?? "";
  const relayHandler = createRelayRequestHandler(runtime, {
    identity: relayIdentity,
    getPublicEndpoint: () => publicEndpoint,
  });
  const discoveryHandler = createDiscoveryRequestHandler(runtime, {
    localRelayId: relayIdentity.relayId,
  });
  const discoveryHandleHandler = createDiscoveryHandleRequestHandler(runtime);
  const discoveryResolveHandler = createDiscoveryResolveRequestHandler(runtime, relayIdentity.relayId);
  const compatRegisterHandler = createCompatRegisterRequestHandler(runtime);
  const server = createServer((request, response) => {
    void (async () => {
      if (await compatRegisterHandler(request, response)) return;
      if (await discoveryHandleHandler(request, response)) return;
      if (await discoveryResolveHandler(request, response)) return;
      if (await discoveryHandler(request, response)) return;
      await relayHandler(request, response);
    })();
  });

  try {
    await new Promise<void>((resolve, reject) => {
      const onError = (error: Error) => {
        server.off("listening", onListening);
        reject(error);
      };
      const onListening = () => {
        server.off("error", onError);
        resolve();
      };
      server.once("error", onError);
      server.once("listening", onListening);
      server.listen(port, host);
    });
  } catch (error) {
    await postgresPersistence?.close().catch(() => undefined);
    throw error;
  }

  const address = server.address();
  if (!address || typeof address === "string") {
    await closeHttpServer(server);
    await postgresPersistence?.close().catch(() => undefined);
    throw new Error("Impossible de déterminer le port Quantic Relay.");
  }

  const actualPort = address.port;
  const url = `http://${urlHost(host)}:${actualPort}`;
  if (!publicEndpoint) publicEndpoint = url;

  await bootstrapDiscoveryPeers(
    runtime,
    relayIdentity.relayId,
    options.bootstrapEndpoints ?? [],
  );

  let retryTask: Promise<void> | null = null;
  const runFederationRetry = () => {
    if (retryTask) return retryTask;
    retryTask = retryPendingFederationReceipts(runtime)
      .catch(() => undefined)
      .finally(() => {
        retryTask = null;
      });
    return retryTask;
  };
  const retryTimer = setInterval(() => {
    void runFederationRetry();
  }, 1_000);
  retryTimer.unref();
  void runFederationRetry();

  let closing: Promise<void> | null = null;
  const close = () => {
    if (!closing) {
      closing = (async () => {
        clearInterval(retryTimer);
        await closeHttpServer(server);
        if (retryTask) await retryTask;
        await runtime.flush();
        await postgresPersistence?.close();
      })();
    }
    return closing;
  };

  return {
    host,
    port: actualPort,
    url,
    dataDir,
    relayId: relayIdentity.relayId,
    close,
  };
}
