import { NextResponse } from "next/server";
import { RelayError, resolveIdentity } from "@/lib/quantic/relay";

export async function GET(request: Request) {
  try {
    const url = new URL(request.url);
    const handle = url.searchParams.get("handle") ?? "";
    return NextResponse.json(resolveIdentity(handle));
  } catch (error) {
    if (error instanceof RelayError) {
      return NextResponse.json({ error: error.message }, { status: error.status });
    }
    return NextResponse.json({ error: "Requête Quantic invalide." }, { status: 400 });
  }
}
