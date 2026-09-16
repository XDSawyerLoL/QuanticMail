import { NextResponse } from "next/server";
import { registerAuthorizedDevice, RelayError } from "@/lib/quantic/relay";

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const result = registerAuthorizedDevice({
      certificate: body.certificate,
      authToken: String(body.authToken ?? ""),
    });
    return NextResponse.json(result, { status: 201 });
  } catch (error) {
    if (error instanceof RelayError) {
      return NextResponse.json({ error: error.message }, { status: error.status });
    }
    return NextResponse.json({ error: "Certificat d’appareil Quantic invalide." }, { status: 400 });
  }
}
