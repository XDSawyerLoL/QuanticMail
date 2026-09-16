import { NextResponse } from "next/server";
import { claimPreKey, PreKeyRelayError } from "@/lib/quantic/prekey-relay";

function bearer(request: Request) {
  const value = request.headers.get("authorization");
  return value?.startsWith("Bearer ") ? value.slice(7) : null;
}

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const record = await claimPreKey({
      senderLocator: String(body.from ?? ""),
      senderAuthToken: bearer(request),
      senderDeviceId: String(body.fromDeviceId ?? ""),
      recipientCanonicalAddress: String(body.to ?? ""),
      recipientDeviceId: String(body.toDeviceId ?? ""),
    });
    if (!record) return NextResponse.json({ prekey: null }, { status: 404 });
    return NextResponse.json({ prekey: record });
  } catch (error) {
    if (error instanceof PreKeyRelayError) {
      return NextResponse.json({ error: error.message }, { status: error.status });
    }
    return NextResponse.json({ error: "Réclamation de prekey impossible." }, { status: 400 });
  }
}
