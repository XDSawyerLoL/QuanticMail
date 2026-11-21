import type { IncomingMessage, ServerResponse } from "node:http";

// A coarse shared circuit breaker, not per-user authentication or DDoS protection.
// Static keys prevent attackers from allocating arbitrary database rows.
// All instances sharing a database and enabling this guard share the same budget.
const LIMITS = Object.freeze({
  "/api/quantic/challenge": 120,
  "/api/quantic/register": 120,
  "/api/quantic/devices/register": 120,
  "/api/quantic/pairing/invite": 60,
  "/api/quantic/pairing/request": 60,
  "/api/quantic/pairing/package": 120,
});
type Scope = keyof typeof LIMITS;
type Query = (sql: string, params?: unknown[]) => Promise<{rows: unknown[]}>;
export type SharedAuthRateLimiter = {
  consume(scope: Scope): Promise<boolean>;
};

export function limitedAuthScope(method: string | undefined, raw: string | undefined): Scope | null {
  if (method !== "POST") return null;
  const path = new URL(raw ?? "/", "http://quantic-relay.local").pathname;
  return Object.hasOwn(LIMITS, path) ? path as Scope : null;
}

export async function createPostgresAuthRateLimiter(query: Query): Promise<SharedAuthRateLimiter> {
  await query(`CREATE TABLE IF NOT EXISTS quantic_auth_rate_v1 (
    scope TEXT PRIMARY KEY,
    epoch BIGINT NOT NULL,
    attempts INTEGER NOT NULL CHECK (attempts >= 1)
  )`);
  return {
    async consume(scope) {
      if (!Object.hasOwn(LIMITS, scope)) throw new Error("Invalid rate limit scope.");
      // One atomic row operation. Database time, no client clock or proxy inputs.
      // An older epoch can never replace a newer epoch, including after clock rollback.
      const result = await query(`
        INSERT INTO quantic_auth_rate_v1 AS counter (scope, epoch, attempts)
        VALUES ($1, floor(extract(epoch FROM clock_timestamp()) / 60)::bigint, 1)
        ON CONFLICT (scope) DO UPDATE
          SET epoch = EXCLUDED.epoch, attempts = CASE
            WHEN counter.epoch < EXCLUDED.epoch THEN 1
            ELSE counter.attempts + 1 END
          WHERE counter.epoch < EXCLUDED.epoch
            OR (counter.epoch = EXCLUDED.epoch AND counter.attempts < $2)
        RETURNING attempts
      `, [scope, LIMITS[scope]]);
      return result.rows.length === 1;
    },
  };
}

export async function rejectOverAuthBudget(
  request: IncomingMessage,
  response: ServerResponse,
  limiter: SharedAuthRateLimiter | undefined,
): Promise<boolean> {
  if (!limiter) return false;
  const scope = limitedAuthScope(request.method, request.url);
  if (!scope) return false;
  let status = 429;
  try {
    if (await limiter.consume(scope)) return false;
  } catch {
    status = 503; // No per-process fallback on shared storage failure.
  }
  response.statusCode = status;
  response.shouldKeepAlive = false;
  response.setHeader("Connection", "close");
  response.setHeader("Cache-Control", "no-store");
  response.setHeader("Content-Type", "application/json; charset=utf-8");
  response.setHeader("Access-Control-Allow-Origin", "*");
  response.setHeader("Retry-After", status === 429 ? "60" : "10");
  response.end(JSON.stringify({error: status === 429 ? "Limite temporaire d’authentification." : "Contrôle d’authentification indisponible."}));
  return true;
}
