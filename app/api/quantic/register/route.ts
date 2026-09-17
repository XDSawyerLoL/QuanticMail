import { NextResponse } from "next/server";
import { registerIdentityCompat } from "@/lib/quantic/register-compat";
import { RelayError } from "@/lib/quantic/relay";

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const result = registerIdentityCompat({
      handle: String(body.handle ?? ""),
      publicKey: body.publicKey ?? {},
      signingPublicKey: body.signingPublicKey ?? {},
      authToken: String(body.authToken ?? ""),
      deviceId: typeof body.deviceId === "string" ? body.deviceId : undefined,
      challenge: typeof body.challenge === "string" ? body.challenge : undefined,
      signature: typeof body.signature === "string" ? body.signature : undefined,
    });
    return NextResponse.json(result, { status: 201 });
  } catch (error) {
    if (error instanceof RelayError) {
      return NextResponse.json({ error: error.message }, { status: error.status });
    }
    return NextResponse.json({ error: "Requête Quantic invalide." }, { status: 400 });
  }
}
