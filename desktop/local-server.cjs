"use strict";
const { createServer, request: httpRequest } = require("node:http");
const { createReadStream, statSync } = require("node:fs");
const { extname, join, relative, resolve } = require("node:path");

const MAIL_PORT = 18787;
const RELAY_PORT = 18788;
const LOCAL_MAIL_URL = `http://127.0.0.1:${MAIL_PORT}/mail/`;

const TYPES = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".ico": "image/x-icon",
  ".webp": "image/webp",
  ".woff": "font/woff",
  ".woff2": "font/woff2",
  ".ttf": "font/ttf",
  ".txt": "text/plain; charset=utf-8"
};

function resolveStaticPath(root, urlPath) {
  if (!urlPath.startsWith("/mail/")) return null;
  let relativePath;
  try { relativePath = decodeURIComponent(urlPath.slice("/mail/".length)); } catch { return null; }
  if (relativePath.includes("\\") || relativePath.includes("\0")) return null;
  const filePath = resolve(root, relativePath, (!relativePath || relativePath.endsWith("/")) ? "index.html" : "");
  const htmlFallback = extname(filePath) ? filePath : join(filePath, "index.html");
  const rel = relative(root, htmlFallback);
  if (rel.startsWith("..") || rel.startsWith("/") || rel === "") return null;
  return htmlFallback;
}

// Allow only loopback hostnames, with the exact listener port. Chromium may
// canonicalize the loopback host as localhost rather than 127.0.0.1 on Windows.
function approvedHost(host, port) {
  if (typeof host !== "string") return false;
  const normalized = host.toLowerCase();
  return normalized === `127.0.0.1:${port}` || normalized === `localhost:${port}`;
}

function approvedOrigin(origin, host) {
  if (origin === undefined) return true;
  if (typeof origin !== "string" || typeof host !== "string") return false;
  // Do not trust "null", file://, a similar hostname, or a different port.
  try {
    const parsed = new URL(origin);
    return parsed.origin === `http://${host.toLowerCase()}`;
  } catch { return false; }
}

function rejectLocalRequest(response, reason) {
  // Explicit JSON prevents all three gateway rejections from being
  // misidentified as a cryptographic manifest failure ("Erreur 403").
  const messages = {
    host: "Quantic Mail Windows : hôte local non autorisé (port ou nom différent).",
    origin: "Quantic Mail Windows : origine de la requête différente de l'application.",
    crossSite: "Quantic Mail Windows : requête intersite bloquée par le serveur local."
  };
  response.writeHead(403, {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
    "x-quantic-local-guard": reason
  });
  response.end(JSON.stringify({ error: messages[reason] || "Requête locale refusée.", code: `LOCAL_GATEWAY_${reason.toUpperCase()}` }));
}

function startLocalServer({ staticRoot, port = MAIL_PORT, relayPort = RELAY_PORT }) {
  const root = resolve(staticRoot);
  const server = createServer((incoming, outgoing) => {
    const host = incoming.headers.host;
    if (!approvedHost(host, port)) {
      rejectLocalRequest(outgoing, "host");
      return;
    }
    const origin = incoming.headers.origin;
    if (!approvedOrigin(origin, host)) {
      rejectLocalRequest(outgoing, "origin");
      return;
    }
    if (incoming.headers["sec-fetch-site"] === "cross-site") {
      rejectLocalRequest(outgoing, "crossSite");
      return;
    }
    let path;
    try { path = new URL(incoming.url, LOCAL_MAIL_URL).pathname; }
    catch { outgoing.writeHead(400).end(); return; }

    if (path.startsWith("/api/quantic/")) {
      const proxy = httpRequest({
        hostname: "127.0.0.1",
        port: relayPort,
        path: incoming.url,
        method: incoming.method,
        headers: { ...incoming.headers, host: `127.0.0.1:${relayPort}` },
        timeout: 15000
      }, (res) => {
        outgoing.writeHead(res.statusCode || 502, res.headers);
        res.pipe(outgoing);
      });
      proxy.on("error", () => {
        if (!outgoing.headersSent) outgoing.writeHead(502, { "content-type": "application/json" });
        outgoing.end(JSON.stringify({ error: "Relais Quantic local indisponible." }));
      });
      incoming.pipe(proxy);
      return;
    }

    if (path === "/") {
      outgoing.writeHead(302, { location: "/mail/" }).end();
      return;
    }
    if (!["GET", "HEAD"].includes(incoming.method || "")) {
      outgoing.writeHead(405).end();
      return;
    }
    const filename = resolveStaticPath(root, path);
    if (!filename) { outgoing.writeHead(404).end(); return; }
    try {
      const info = statSync(filename);
      if (!info.isFile()) throw new Error("Not a file");
      outgoing.writeHead(200, {
        "content-type": TYPES[extname(filename).toLowerCase()] || "application/octet-stream",
        "content-length": info.size,
        "x-content-type-options": "nosniff",
        "referrer-policy": "no-referrer",
        "cache-control": path.includes("/_next/static/") ? "public, max-age=31536000, immutable" : "no-store"
      });
      if (incoming.method === "HEAD") { outgoing.end(); return; }
      createReadStream(filename).pipe(outgoing);
    } catch {
      outgoing.writeHead(404).end();
    }
  });
  return new Promise((res, rej) => {
    server.once("error", rej);
    server.listen(port, "127.0.0.1", () => {
      server.off("error", rej);
      res({ server, url: `http://127.0.0.1:${port}/mail/` });
    });
  });
}

module.exports = { MAIL_PORT, RELAY_PORT, LOCAL_MAIL_URL, approvedHost, approvedOrigin, resolveStaticPath, startLocalServer };
