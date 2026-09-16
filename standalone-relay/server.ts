import { createServer, type Server } from "node:http";

import { createRelayRequestHandler } from "./http.ts";
import { RelayRuntime } from "./runtime.ts";
import { createFileRelayStateStore } from "./storage.ts";

export type RelayServerOptions = {
  host?: string;
  port?: number;
  dataDir?: string;
};

export type RunningRelayServer = {
  host: string;
  port: number;
  url: string;
  dataDir: string;
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

  const store = createFileRelayStateStore(dataDir);
  const runtime = new RelayRuntime(store);
  await runtime.initialize();

  const handler = createRelayRequestHandler(runtime);
  const server = createServer((request, response) => {
    void handler(request, response);
  });

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

  const address = server.address();
  if (!address || typeof address === "string") {
    await closeHttpServer(server);
    throw new Error("Impossible de déterminer le port Quantic Relay.");
  }

  const actualPort = address.port;
  let closing: Promise<void> | null = null;

  const close = () => {
    if (!closing) {
      closing = (async () => {
        await closeHttpServer(server);
        await runtime.flush();
      })();
    }
    return closing;
  };

  return {
    host,
    port: actualPort,
    url: `http://${urlHost(host)}:${actualPort}`,
    dataDir,
    close,
  };
}
