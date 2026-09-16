import { NextResponse } from "next/server";
import { registryStatus } from "@/lib/quantic/registry-store";

export async function GET() {
  return NextResponse.json(registryStatus());
}
