import { NextResponse } from "next/server";
import { createPairingInvite, PairingRelayError } from "@/lib/quantic/pairing-relay";

function bearer(request: Request) {
  const value = request.headers.get("authorization");
  return value?.startsWith("Bearer ") ? value.slice(7) : null;
}

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const result = await createPairingInvite({
      locator: String(body.handle ?? body.canonicalAddress ?? ""),
      authToken: bearer(request),
      rootDeviceId: String(body.rootDeviceId ?? ""),
      secret: String(body.secret ?? ""),
    });
    return NextResponse.json(result, { status: 201 });
  } catch (error) {
    if (error instanceof PairingRelayError) {
      return NextResponse.json({ error: error.message }, { status: error.status });
    }
    return NextResponse.json({ error: "Création de l’invitation impossible." }, { status: 400 });
  }
}
