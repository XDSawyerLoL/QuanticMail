import { NextResponse } from "next/server";
import { activeDevices } from "@/lib/quantic/manifest-core.mjs";
import { getManifest } from "@/lib/quantic/manifest-state";
import { registerAuthorizedDevice, RelayError } from "@/lib/quantic/relay";

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const certificate = body.certificate;
    const canonicalAddress = String(certificate?.payload?.canonicalAddress ?? "").toLowerCase();
    const deviceId = String(certificate?.payload?.deviceId ?? "");
    if (canonicalAddress && deviceId) {
      const manifest = await getManifest(canonicalAddress);
      if (manifest && !activeDevices(manifest).some((device) => device.deviceId === deviceId)) {
        return NextResponse.json(
          { error: "Cet appareil n’est pas autorisé par le manifeste Quantic courant ou a été révoqué." },
          { status: 401 },
        );
      }
    }

    const result = registerAuthorizedDevice({
      certificate,
      authToken: String(body.authToken ?? ""),
    });
    return NextResponse.json(result, { status: 201 });
  } catch (error) {
    if (error instanceof RelayError) {
      return NextResponse.json({ error: error.message }, { status: error.status });
    }
    return NextResponse.json({ error: "Certificat d’appareil Quantic invalide." }, { status: 400 });
  }
}
