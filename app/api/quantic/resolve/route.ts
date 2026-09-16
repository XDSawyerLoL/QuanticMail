import { NextResponse } from "next/server";
import { activeDevices } from "@/lib/quantic/manifest-core.mjs";
import { getManifest } from "@/lib/quantic/manifest-state";
import { RelayError, resolveIdentity } from "@/lib/quantic/relay";

const CANONICAL = /^[a-z0-9][a-z0-9._-]{2,31}~[0-9a-f]{10}@quantic$/;

function manifestIdentity(manifest: Awaited<ReturnType<typeof getManifest>>) {
  if (!manifest) return null;
  const payload = manifest.payload;
  return {
    address: `${payload.handle}@quantic`,
    canonicalAddress: payload.canonicalAddress,
    fingerprint: payload.fingerprint,
    publicKey: payload.identityPublicKey,
    signingPublicKey: payload.identitySigningPublicKey,
    devices: activeDevices(manifest).map((device) => ({
      deviceId: device.deviceId,
      label: device.label,
      publicKey: device.publicKey,
      kind: device.kind,
    })),
    manifest,
  };
}

export async function GET(request: Request) {
  const url = new URL(request.url);
  const handle = (url.searchParams.get("handle") ?? "").trim().toLowerCase();
  try {
    const live = resolveIdentity(handle);
    const manifest = await getManifest(live.canonicalAddress);
    const fromManifest = manifestIdentity(manifest);
    return NextResponse.json(fromManifest ?? { ...live, manifest: null });
  } catch (error) {
    if (error instanceof RelayError && error.status === 404 && CANONICAL.test(handle)) {
      const manifest = await getManifest(handle);
      const fromManifest = manifestIdentity(manifest);
      if (fromManifest) return NextResponse.json(fromManifest);
    }
    if (error instanceof RelayError) {
      return NextResponse.json({ error: error.message }, { status: error.status });
    }
    return NextResponse.json({ error: "Requête Quantic invalide." }, { status: 400 });
  }
}
