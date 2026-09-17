import { NextResponse } from "next/server";
import { activeDevices } from "@/lib/quantic/manifest-core.mjs";
import {
  acceptManifestInMemory,
  getManifest,
  ManifestStateError,
} from "@/lib/quantic/manifest-state";
import { loadRegistryManifestsByHandle } from "@/lib/quantic/registry-store";
import { RelayError, resolveIdentity } from "@/lib/quantic/relay";
import type { QuanticIdentityManifest } from "@/lib/quantic/manifest-types";

const CANONICAL = /^[a-z0-9][a-z0-9._-]{2,31}~(?:[0-9a-f]{10}|[0-9a-f]{32})@quantic$/;

function manifestIdentity(manifest: QuanticIdentityManifest | null) {
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
      deviceSigningPublicKey: device.deviceSigningPublicKey,
      kind: device.kind,
    })),
    manifest,
  };
}

async function durableShortHandleIdentity(handle: string) {
  const candidates = await loadRegistryManifestsByHandle(handle);
  const accepted: QuanticIdentityManifest[] = [];
  for (const candidate of candidates) {
    try {
      accepted.push(acceptManifestInMemory(candidate));
    } catch (error) {
      if (error instanceof ManifestStateError && error.status === 401) continue;
      throw error;
    }
  }

  if (accepted.length > 1) {
    return NextResponse.json(
      {
        error: `${handle.replace(/@quantic$/i, "")}@quantic est ambigu. Utilisez l’adresse Quantic canonique avec son empreinte.`,
      },
      { status: 409 },
    );
  }
  return accepted.length === 1 ? NextResponse.json(manifestIdentity(accepted[0])) : null;
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
    if (error instanceof RelayError && error.status === 404) {
      if (CANONICAL.test(handle)) {
        const manifest = await getManifest(handle);
        const fromManifest = manifestIdentity(manifest);
        if (fromManifest) return NextResponse.json(fromManifest);
      } else {
        try {
          const durable = await durableShortHandleIdentity(handle);
          if (durable) return durable;
        } catch (registryError) {
          if (registryError instanceof ManifestStateError) {
            return NextResponse.json({ error: registryError.message }, { status: registryError.status });
          }
          return NextResponse.json(
            { error: "Registre Quantic durable temporairement indisponible." },
            { status: 503 },
          );
        }
      }
    }
    if (error instanceof RelayError) {
      return NextResponse.json({ error: error.message }, { status: error.status });
    }
    return NextResponse.json({ error: "Requête Quantic invalide." }, { status: 400 });
  }
}
