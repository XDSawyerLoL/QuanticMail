import { NextResponse } from "next/server";
import { PreKeyRelayError, publishPreKeys } from "@/lib/quantic/prekey-relay";

function bearer(request: Request) {
  const value = request.headers.get("authorization");
  return value?.startsWith("Bearer ") ? value.slice(7) : null;
}

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const result = await publishPreKeys({
      locator: String(body.handle ?? body.canonicalAddress ?? ""),
      authToken: bearer(request),
      deviceId: String(body.deviceId ?? ""),
      records: Array.isArray(body.records) ? body.records : [],
    });
    return NextResponse.json(result);
  } catch (error) {
    if (error instanceof PreKeyRelayError) {
      return NextResponse.json({ error: error.message }, { status: error.status });
    }
    return NextResponse.json({ error: "Publication des prekeys impossible." }, { status: 400 });
  }
}
