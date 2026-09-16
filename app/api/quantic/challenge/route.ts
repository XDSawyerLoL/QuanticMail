import { NextResponse } from "next/server";
import { createIdentityChallenge, RelayError } from "@/lib/quantic/relay";

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const result = createIdentityChallenge({
      handle: String(body.handle ?? ""),
      publicKey: body.publicKey ?? {},
      signingPublicKey: body.signingPublicKey ?? {},
    });
    return NextResponse.json(result, { status: 201 });
  } catch (error) {
    if (error instanceof RelayError) {
      return NextResponse.json({ error: error.message }, { status: error.status });
    }
    return NextResponse.json({ error: "Défi Quantic invalide." }, { status: 400 });
  }
}
