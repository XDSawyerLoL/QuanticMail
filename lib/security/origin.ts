import type { NextRequest } from "next/server";

export function hasTrustedOrigin(request: NextRequest) {
  const origin = request.headers.get("origin");
  if (!origin) return process.env.NODE_ENV !== "production";

  try {
    const candidate = new URL(origin);
    if (candidate.username || candidate.password || candidate.origin !== origin ||
        (candidate.protocol !== "https:" && candidate.protocol !== "http:")) return false;
    const allowed = new Set([request.nextUrl.origin]);
    for (const entry of (process.env.QUANTIC_TRUSTED_ORIGINS ?? "").split(",")) {
      const value = entry.trim();
      if (!value) continue;
      try {
        const configured = new URL(value);
        if (configured.protocol === "https:" && configured.origin === value) allowed.add(value);
      } catch { /* invalid configured origin ignored */ }
    }
    return allowed.has(candidate.origin);
  } catch {
    return false;
  }
}
