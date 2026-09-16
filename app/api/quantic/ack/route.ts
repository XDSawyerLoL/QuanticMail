import { NextResponse } from "next/server";
import { assertManifestDeviceActive, ManifestStateError } from "@/lib/quantic/manifest-state";
import { acknowledgeEnvelopes, RelayError } from "@/lib/quantic/relay";

function bearer(request: Request) {
  const value = request.headers.get("authorization");
  return value?.startsWith("Bearer ") ? value.slice(7) : null;
}

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const handle = String(body.handle ?? "");
    const deviceId = typeof body.deviceId === "string" ? body.deviceId : undefined;
    if (deviceId) assertManifestDeviceActive(handle, deviceId);
    const result = acknowledgeEnvelopes(
      handle,
      bearer(request),
      deviceId,
      Array.isArray(body.ids) ? body.ids : [],
    );
    return NextResponse.json(result);
  } catch (error) {
    if (error instanceof ManifestStateError || error instanceof RelayError) {
      return NextResponse.json({ error: error.message }, { status: error.status });
    }
    return NextResponse.json({ error: "Requête Quantic invalide." }, { status: 400 });
  }
}
