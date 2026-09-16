import { NextResponse } from "next/server";
import { registerIdentity, RelayError } from "@/lib/quantic/relay";

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const result = registerIdentity({
      handle: String(body.handle ?? ""),
      publicKey: body.publicKey ?? {},
      authToken: String(body.authToken ?? ""),
    });
    return NextResponse.json(result, { status: 201 });
  } catch (error) {
    if (error instanceof RelayError) {
      return NextResponse.json({ error: error.message }, { status: error.status });
    }
    return NextResponse.json({ error: "Requête Quantic invalide." }, { status: 400 });
  }
}
