import { NextResponse } from "next/server";
import { createIdentityChallenge, RelayError } from "@/lib/quantic/relay";

import { readBoundedJson, RequestBodyError } from "@/lib/security/bounded-json";
import { consumeRateLimit } from "@/lib/security/rate-limit";

export async function POST(request: Request) {
  try {
    const budget = consumeRateLimit("quantic-public-challenge", 120, 60_000);
    if (!budget.ok) return NextResponse.json({error:"Limite temporaire de défis."}, {status:429, headers:{"Retry-After":String(budget.retryAfter)}});
    const body = await readBoundedJson(request, 8192);
    const result = createIdentityChallenge({
      handle: String(body.handle ?? ""),
      publicKey: (body.publicKey ?? {}) as JsonWebKey,
      signingPublicKey: (body.signingPublicKey ?? {}) as JsonWebKey,
    });
    return NextResponse.json(result, { status: 201 });
  } catch (error) {
    if (error instanceof RelayError || error instanceof RequestBodyError) {
      return NextResponse.json({ error: error.message }, { status: error.status });
    }
    return NextResponse.json({ error: "Défi Quantic invalide." }, { status: 400 });
  }
}
