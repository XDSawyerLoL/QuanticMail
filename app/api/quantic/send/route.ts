import { NextResponse } from "next/server";
import { hasUnsupportedNativeFields } from "@/lib/quantic/legacy-native-boundary.mjs";
import {
  assertCurrentManifestDeviceActive,
  ManifestStateError,
} from "@/lib/quantic/manifest-state";
import { authenticateLocalDevice, resolveIdentity, enqueueEnvelope, RelayError } from "@/lib/quantic/relay";

function bearer(request: Request) {
  const value = request.headers.get("authorization");
  return value?.startsWith("Bearer ") ? value.slice(7) : null;
}

export async function POST(request: Request) {
  try {
    const body = await request.json();
    if (hasUnsupportedNativeFields(body)) return NextResponse.json({error:"Format cryptographique non pris en charge par cette route classique."},{status:400});
    const from = String(body.from ?? "");
    const fromDeviceId = typeof body.fromDeviceId === "string" ? body.fromDeviceId : undefined;
    const to = String(body.to ?? "");
    const toDeviceId = String(body.toDeviceId ?? "");
    const token = bearer(request);
    const sender = authenticateLocalDevice(from, token, fromDeviceId);
    const recipient = resolveIdentity(to);
    await assertCurrentManifestDeviceActive(sender.canonicalAddress, sender.deviceId);
    await assertCurrentManifestDeviceActive(recipient.canonicalAddress, toDeviceId);

    const result = enqueueEnvelope({
      clientMessageId: String(body.clientMessageId ?? ""),
      from: sender.canonicalAddress,
      fromDeviceId: sender.deviceId,
      to: recipient.canonicalAddress,
      toDeviceId,
      authToken: token,
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
