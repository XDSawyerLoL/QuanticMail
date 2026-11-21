import { NextRequest, NextResponse } from "next/server";
import { destroySession } from "@/lib/auth/session";
import { hasTrustedOrigin } from "@/lib/security/origin";

export async function POST(request: NextRequest) {
  if (!hasTrustedOrigin(request)) {
    return NextResponse.json({ error: "Origine invalide." }, { status: 403 });
  }

  try { await destroySession(); } catch {
    return NextResponse.json({error:"Autorité de session indisponible. Déconnexion non confirmée."},{status:503});
  }
  return NextResponse.json({ ok: true });
}
