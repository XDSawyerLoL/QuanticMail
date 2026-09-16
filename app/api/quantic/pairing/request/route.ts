import { NextResponse } from "next/server";
import { PairingRelayError, submitPairingDeviceRequest } from "@/lib/quantic/pairing-relay";

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const result = submitPairingDeviceRequest({
      inviteId: String(body.inviteId ?? ""),
      secret: String(body.secret ?? ""),
      request: body.request,
    });
    return NextResponse.json(result, { status: 202 });
  } catch (error) {
    if (error instanceof PairingRelayError) {
      return NextResponse.json({ error: error.message }, { status: error.status });
    }
    return NextResponse.json({ error: "Demande de pairing impossible." }, { status: 400 });
  }
}
