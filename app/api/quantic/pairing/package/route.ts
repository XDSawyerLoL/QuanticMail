import { NextResponse } from "next/server";
import {
  PairingRelayError,
  storePairingPackage,
  takeEncryptedPairingPackage,
} from "@/lib/quantic/pairing-relay";

function bearer(request: Request) {
  const value = request.headers.get("authorization");
  return value?.startsWith("Bearer ") ? value.slice(7) : null;
}

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const mode = String(body.mode ?? "take");
    if (mode === "put") {
      const result = await storePairingPackage({
        locator: String(body.handle ?? body.canonicalAddress ?? ""),
        authToken: bearer(request),
        rootDeviceId: String(body.rootDeviceId ?? ""),
        inviteId: String(body.inviteId ?? ""),
        secret: String(body.secret ?? ""),
        encryptedPackage: body.package,
      });
      return NextResponse.json(result, { status: 201 });
    }
    const encryptedPackage = takeEncryptedPairingPackage(
      String(body.inviteId ?? ""),
      String(body.secret ?? ""),
    );
    return NextResponse.json({ package: encryptedPackage });
  } catch (error) {
    if (error instanceof PairingRelayError) {
      return NextResponse.json({ error: error.message }, { status: error.status });
    }
    return NextResponse.json({ error: "Paquet de pairing indisponible." }, { status: 400 });
  }
}
