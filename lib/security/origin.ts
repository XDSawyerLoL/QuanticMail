import type { NextRequest } from "next/server";

export function hasTrustedOrigin(request: NextRequest) {
  const origin = request.headers.get("origin");
  if (!origin) return process.env.NODE_ENV !== "production";

  try {
    return new URL(origin).host === request.nextUrl.host;
  } catch {
    return false;
  }
}
