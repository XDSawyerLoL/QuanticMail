import type { NextConfig } from "next";

export default function retiredWebConfiguration(): NextConfig {
  throw new Error("Quantic Sillage: legacy runtime retired; use the native installer. No data was modified.");
}
