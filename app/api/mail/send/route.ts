import { NextRequest, NextResponse } from "next/server";
import { readSession } from "@/lib/auth/session";
import { sendMessage } from "@/lib/mail/service";
import { consumeRateLimit } from "@/lib/security/rate-limit";
import { hasTrustedOrigin } from "@/lib/security/origin";

export async function POST(request: NextRequest) {
  if (!hasTrustedOrigin(request)) {
    return NextResponse.json({ error: "Origine invalide." }, { status: 403 });
  }

  const session = await readSession();
  if (!session) {
    return NextResponse.json({ error: "Session expirée." }, { status: 401 });
  }

  const rate = consumeRateLimit(`send:${session.email}`, 30, 60 * 60 * 1000);
  if (!rate.ok) {
    return NextResponse.json(
      { error: "Limite d’envoi temporaire atteinte." },
      { status: 429, headers: { "Retry-After": String(rate.retryAfter) } },
    );
  }

  let payload: { to?: string; subject?: string; body?: string };
  try {
    payload = (await request.json()) as { to?: string; subject?: string; body?: string };
  } catch {
    return NextResponse.json({ error: "Requête invalide." }, { status: 400 });
  }

  const to = payload.to?.trim();
  const subject = payload.subject?.trim() || "(Sans objet)";
  const body = payload.body?.trim();
  if (!to || !to.includes("@") || !body) {
    return NextResponse.json({ error: "Destinataire et message requis." }, { status: 400 });
  }

  if (to.length > 320 || subject.length > 998 || body.length > 2_000_000) {
    return NextResponse.json({ error: "Message trop volumineux." }, { status: 413 });
  }

  try {
    const result = await sendMessage(session, { to, subject, body });
    return NextResponse.json({ ok: true, ...result });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Échec de l’envoi.";
    return NextResponse.json({ error: message }, { status: 502 });
  }
}
