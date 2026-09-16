import { NextResponse } from "next/server";
import {
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
    return NextResponse.json({ receipts: pullReceipts(handle, bearer(request)) });
  } catch (error) {
    if (error instanceof RelayError) {
      return NextResponse.json({ error: error.message }, { status: error.status });
    }
    return NextResponse.json({ error: "Requête Quantic invalide." }, { status: 400 });
  }
}

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const result = acknowledgeReceipts(
      String(body.handle ?? ""),
      bearer(request),
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
