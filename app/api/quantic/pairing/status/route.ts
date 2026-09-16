import { NextResponse } from "next/server";
import {
  PairingRelayError,
  readPairingDeviceRequest,
  readPairingStatus,
} from "@/lib/quantic/pairing-relay";

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const inviteId = String(body.inviteId ?? "");
    const secret = String(body.secret ?? "");
    const status = readPairingStatus(inviteId, secret);
    const deviceRequest = status.hasRequest ? readPairingDeviceRequest(inviteId, secret) : null;
    return NextResponse.json({ ...status, request: deviceRequest });
  } catch (error) {
    if (error instanceof PairingRelayError) {
      return NextResponse.json({ error: error.message }, { status: error.status });
    }
    return NextResponse.json({ error: "Statut de pairing indisponible." }, { status: 400 });
  }
}
