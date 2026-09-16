import { NextRequest, NextResponse } from "next/server";
import { readSession } from "@/lib/auth/session";
import { getMailSnapshot } from "@/lib/mail/service";

export async function GET(request: NextRequest) {
  const session = await readSession();
  if (!session) {
    return NextResponse.json({ error: "Session expirée." }, { status: 401 });
  }

  const mailboxId = request.nextUrl.searchParams.get("mailboxId") || undefined;

  try {
    const snapshot = await getMailSnapshot(session, mailboxId);
    return NextResponse.json(snapshot);
  } catch (error) {
    const message = error instanceof Error ? error.message : "Impossible de charger la boîte.";
    return NextResponse.json({ error: message }, { status: 502 });
  }
}
