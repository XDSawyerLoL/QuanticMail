type Bucket = { count: number; resetAt: number };
const buckets = new Map<string, Bucket>();
const MAX_BUCKETS = 100_000;
let nextSweep = 0;

// Local resource guard only. Not shared across processes or a replacement for
// an authenticated, durable distributed rate limiter at the relay.
export function consumeRateLimit(key: string, limit = 10, windowMs = 10 * 60 * 1000) {
  if (typeof key !== "string" || !key.length || key.length > 512 ||
      !Number.isSafeInteger(limit) || limit < 1 ||
      !Number.isSafeInteger(windowMs) || windowMs < 1 || windowMs > 86_400_000) {
    return { ok: false, retryAfter: 60 };
  }
  const now = Math.floor(performance.now());
  if (now >= nextSweep) {
    for (const [id, value] of buckets) if (value.resetAt <= now) buckets.delete(id);
    nextSweep = now + 10_000;
  }
  const current = buckets.get(key);
  if (!current || current.resetAt <= now) {
    if (!current && buckets.size >= MAX_BUCKETS) {
      return { ok: false, retryAfter: 10 };
    }
    buckets.set(key, { count: 1, resetAt: now + windowMs });
    return { ok: true, retryAfter: 0 };
  }
  if (current.count >= limit) return { ok: false, retryAfter: Math.max(1, Math.ceil((current.resetAt - now) / 1000)) };
  current.count += 1;
  return { ok: true, retryAfter: 0 };
}
