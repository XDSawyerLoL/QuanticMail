import { NextResponse } from "next/server";
import {
  getManifest,
  ManifestStateError,
  publishManifest,
} from "@/lib/quantic/manifest-state";
import { normalizeCanonicalAddress } from "@/lib/quantic/registry-path.mjs";
import type { QuanticIdentityManifest } from "@/lib/quantic/manifest-types";

export async function GET(request: Request) {
  const url = new URL(request.url);
  let canonical: string;
  try {
    canonical = normalizeCanonicalAddress(url.searchParams.get("handle") ?? "");
  } catch {
    return NextResponse.json({ error: "Adresse Quantic canonique requise." }, { status: 400 });
  }
  const manifest = await getManifest(canonical);
  if (!manifest) {
    return NextResponse.json({ error: "Aucun manifeste V1.1 publié pour cette identité." }, { status: 404 });
  }
  return NextResponse.json({ manifest });
}

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const manifest = (body?.manifest ?? body) as QuanticIdentityManifest;
    const result = await publishManifest(manifest);
    return NextResponse.json(result, { status: 201 });
  } catch (error) {
    if (error instanceof ManifestStateError) {
      return NextResponse.json({ error: error.message }, { status: error.status });
    }
    return NextResponse.json({ error: "Manifeste Quantic invalide." }, { status: 400 });
  }
}
