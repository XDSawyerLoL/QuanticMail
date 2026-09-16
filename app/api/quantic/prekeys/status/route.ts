import { NextResponse } from "next/server";
import { preKeyStatus, PreKeyRelayError } from "@/lib/quantic/prekey-relay";

function bearer(request: Request) {
  const value = request.headers.get("authorization");
  return value?.startsWith("Bearer ") ? value.slice(7) : null;
}

export async function GET(request: Request) {
  try {
    const url = new URL(request.url);
    const result = await preKeyStatus({
      locator: String(url.searchParams.get("handle") ?? ""),
      authToken: bearer(request),
      deviceId: String(url.searchParams.get("deviceId") ?? ""),
    });
    return NextResponse.json(result);
  } catch (error) {
    if (error instanceof PreKeyRelayError) {
      return NextResponse.json({ error: error.message }, { status: error.status });
    }
    return NextResponse.json({ error: "Statut des prekeys indisponible." }, { status: 400 });
  }
}
