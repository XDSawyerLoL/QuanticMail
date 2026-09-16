import { NextResponse } from "next/server";
import { enqueueEnvelope, RelayError } from "@/lib/quantic/relay";

function bearer(request: Request) {
  const value = request.headers.get("authorization");
  return value?.startsWith("Bearer ") ? value.slice(7) : null;
}

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const result = enqueueEnvelope({
      clientMessageId: String(body.clientMessageId ?? ""),
      from: String(body.from ?? ""),
      fromDeviceId: typeof body.fromDeviceId === "string" ? body.fromDeviceId : undefined,
      to: String(body.to ?? ""),
      toDeviceId: String(body.toDeviceId ?? ""),
      authToken: bearer(request),
      ciphertext: String(body.ciphertext ?? ""),
      iv: String(body.iv ?? ""),
      ephemeralPublicKey: body.ephemeralPublicKey ?? {},
    });
    return NextResponse.json(result, { status: 202 });
  } catch (error) {
    if (error instanceof RelayError) {
      return NextResponse.json({ error: error.message }, { status: error.status });
    }
    return NextResponse.json({ error: "Enveloppe Quantic invalide." }, { status: 400 });
  }
}
