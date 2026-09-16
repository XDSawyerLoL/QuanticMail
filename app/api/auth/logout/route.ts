import { NextRequest, NextResponse } from "next/server";
import { destroySession } from "@/lib/auth/session";
import { hasTrustedOrigin } from "@/lib/security/origin";

export async function POST(request: NextRequest) {
  if (!hasTrustedOrigin(request)) {
    return NextResponse.json({ error: "Origine invalide." }, { status: 403 });
  }

  await destroySession();
  return NextResponse.json({ ok: true });
}
