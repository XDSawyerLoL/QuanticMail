import { NextResponse } from "next/server";
import { assertCurrentManifestDeviceActive, ManifestStateError } from "@/lib/quantic/manifest-state";
import { authenticateLocalDevice, pullEnvelopes, RelayError } from "@/lib/quantic/relay";

function bearer(request: Request) {
  const value = request.headers.get("authorization");
  return value?.startsWith("Bearer ") ? value.slice(7) : null;
}

export async function GET(request: Request) {
  try {
    const url = new URL(request.url);
    const handle = url.searchParams.get("handle") ?? "";
    const deviceId = url.searchParams.get("deviceId");
    const token = bearer(request);
    const authenticated = authenticateLocalDevice(handle, token, deviceId);
    await assertCurrentManifestDeviceActive(authenticated.canonicalAddress, authenticated.deviceId);
    return NextResponse.json({ envelopes: pullEnvelopes(authenticated.canonicalAddress, token, authenticated.deviceId) });
  } catch (error) {
    if (error instanceof ManifestStateError || error instanceof RelayError) {
      return NextResponse.json({ error: error.message }, { status: error.status });
    }
    return NextResponse.json({ error: "Requête Quantic invalide." }, { status: 400 });
  }
}
