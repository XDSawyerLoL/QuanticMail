import { NextResponse } from "next/server";
import {
  ManifestStateError,
  publishManifest,
} from "@/lib/quantic/manifest-state";
import type { QuanticIdentityManifest } from "@/lib/quantic/manifest-types";

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const manifest = body?.manifest as QuanticIdentityManifest;
    if (!manifest) {
      return NextResponse.json({ error: "Manifeste signé requis." }, { status: 400 });
    }
    const result = await publishManifest(manifest);
    return NextResponse.json(result);
  } catch (error) {
    if (error instanceof ManifestStateError) {
      return NextResponse.json({ error: error.message }, { status: error.status });
    }
    return NextResponse.json({ error: "Révocation Quantic invalide." }, { status: 400 });
  }
}
