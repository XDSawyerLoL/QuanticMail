import { NextResponse } from "next/server";
import { acknowledgeEnvelopes, RelayError } from "@/lib/quantic/relay";

function bearer(request: Request) {
  const value = request.headers.get("authorization");
  return value?.startsWith("Bearer ") ? value.slice(7) : null;
}

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const result = acknowledgeEnvelopes(
      String(body.handle ?? ""),
      bearer(request),
      typeof body.deviceId === "string" ? body.deviceId : undefined,
      Array.isArray(body.ids) ? body.ids : [],
    );
    return NextResponse.json(result);
  } catch (error) {
    if (error instanceof RelayError) {
      return NextResponse.json({ error: error.message }, { status: error.status });
    }
    return NextResponse.json({ error: "Requête Quantic invalide." }, { status: 400 });
  }
}
