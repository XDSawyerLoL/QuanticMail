import { NextResponse } from "next/server";
import {
  assertManifestDeviceActive,
  ManifestStateError,
} from "@/lib/quantic/manifest-state";
import { enqueueEnvelope, RelayError } from "@/lib/quantic/relay";

function bearer(request: Request) {
  const value = request.headers.get("authorization");
  return value?.startsWith("Bearer ") ? value.slice(7) : null;
}

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const from = String(body.from ?? "");
    const fromDeviceId = typeof body.fromDeviceId === "string" ? body.fromDeviceId : undefined;
    const to = String(body.to ?? "");
    const toDeviceId = String(body.toDeviceId ?? "");
    if (fromDeviceId) assertManifestDeviceActive(from, fromDeviceId);
    assertManifestDeviceActive(to, toDeviceId);

    const result = enqueueEnvelope({
      clientMessageId: String(body.clientMessageId ?? ""),
      from,
      fromDeviceId,
      to,
      toDeviceId,
      authToken: bearer(request),
      ciphertext: String(body.ciphertext ?? ""),
      iv: String(body.iv ?? ""),
      ephemeralPublicKey: body.ephemeralPublicKey ?? {},
    });
    return NextResponse.json(result, { status: 202 });
  } catch (error) {
    if (error instanceof ManifestStateError || error instanceof RelayError) {
      return NextResponse.json({ error: error.message }, { status: error.status });
    }
    return NextResponse.json({ error: "Enveloppe Quantic invalide." }, { status: 400 });
  }
}
