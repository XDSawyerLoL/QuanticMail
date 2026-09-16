import { NextResponse } from "next/server";
import { assertManifestDeviceActive, ManifestStateError } from "@/lib/quantic/manifest-state";
import { pullEnvelopes, RelayError } from "@/lib/quantic/relay";

function bearer(request: Request) {
  const value = request.headers.get("authorization");
  return value?.startsWith("Bearer ") ? value.slice(7) : null;
}

export async function GET(request: Request) {
  try {
    const url = new URL(request.url);
    const handle = url.searchParams.get("handle") ?? "";
    const deviceId = url.searchParams.get("deviceId");
    if (deviceId) assertManifestDeviceActive(handle, deviceId);
    return NextResponse.json({ envelopes: pullEnvelopes(handle, bearer(request), deviceId) });
  } catch (error) {
    if (error instanceof ManifestStateError || error instanceof RelayError) {
      return NextResponse.json({ error: error.message }, { status: error.status });
    }
    return NextResponse.json({ error: "Requête Quantic invalide." }, { status: 400 });
  }
}
