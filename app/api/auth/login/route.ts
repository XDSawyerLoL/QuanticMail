import { NextRequest, NextResponse } from "next/server";
import { createSession } from "@/lib/auth/session";
import { validateMailbox } from "@/lib/mail/service";
import { consumeRateLimit } from "@/lib/security/rate-limit";
import { hasTrustedOrigin } from "@/lib/security/origin";

export async function POST(request: NextRequest) {
  if (!hasTrustedOrigin(request)) {
    return NextResponse.json({ error: "Origine invalide." }, { status: 403 });
  }

  const forwardedFor = request.headers.get("x-forwarded-for")?.split(",")[0]?.trim();
  const key = forwardedFor || "local";
  const rate = consumeRateLimit(`login:${key}`, 10, 10 * 60 * 1000);
  if (!rate.ok) {
    return NextResponse.json(
      { error: "Trop de tentatives. Réessayez plus tard." },
      { status: 429, headers: { "Retry-After": String(rate.retryAfter) } },
    );
  }

  let payload: { email?: string; password?: string };
  try {
    payload = (await request.json()) as { email?: string; password?: string };
  } catch {
    return NextResponse.json({ error: "Requête invalide." }, { status: 400 });
  }

  const email = payload.email?.trim().toLowerCase();
  const password = payload.password;
  if (!email || !password || !email.includes("@")) {
    return NextResponse.json({ error: "Adresse ou mot de passe invalide." }, { status: 400 });
  }

  const authorization = `Basic ${Buffer.from(`${email}:${password}`, "utf8").toString("base64")}`;

  try {
    await validateMailbox(authorization);
    await createSession(email, authorization);
    return NextResponse.json({ ok: true });
  } catch {
    return NextResponse.json({ error: "Connexion impossible. Vérifiez vos identifiants." }, { status: 401 });
  }
}
