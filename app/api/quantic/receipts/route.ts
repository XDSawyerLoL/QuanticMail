import { NextResponse } from "next/server";
import { assertCurrentManifestDeviceActive, ManifestStateError } from "@/lib/quantic/manifest-state";
import {
  authenticateLocalDevice,
  acknowledgeReceipts,
  pullReceipts,
  RelayError,
} from "@/lib/quantic/relay";

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
    return NextResponse.json({ receipts: pullReceipts(authenticated.canonicalAddress, token, authenticated.deviceId) });
  } catch (error) {
    if (error instanceof ManifestStateError || error instanceof RelayError) {
      return NextResponse.json({ error: error.message }, { status: error.status });
    }
    return NextResponse.json({ error: "Requête Quantic invalide." }, { status: 400 });
  }
}

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const handle = String(body.handle ?? "");
    const deviceId = typeof body.deviceId === "string" ? body.deviceId : undefined;
    const token = bearer(request);
    const authenticated = authenticateLocalDevice(handle, token, deviceId);
    await assertCurrentManifestDeviceActive(authenticated.canonicalAddress, authenticated.deviceId);
    const result = acknowledgeReceipts(
      authenticated.canonicalAddress,
      token,
      authenticated.deviceId,
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
