import { cpSync, existsSync, mkdirSync, rmSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { resolve } from "node:path";
import { build } from "esbuild";

const target = resolve("desktop/bundle");
const exported = resolve("out");
const mailTarget = resolve(target, "mail");
const icon = spawnSync(process.execPath, ["scripts/generate-desktop-icon.mjs"], { stdio: "inherit" });
if (icon.status !== 0) process.exit(icon.status || 1);

const exportBuild = spawnSync(process.execPath, ["scripts/build-hostinger-static.mjs"], {
  stdio: "inherit",
  env: { ...process.env, NEXT_PUBLIC_QUANTIC_BOOTSTRAPS: "", NEXT_PUBLIC_QUANTIC_IDENTITY_GATE_ENABLED: "true", NEXT_PUBLIC_QUANTIC_DESKTOP: "true" }
});
if (exportBuild.status !== 0) process.exit(exportBuild.status || 1);
if (!existsSync(resolve(exported, "index.html"))) {
  throw new Error("Export QuanticMail manquant : out/index.html.");
}
rmSync(target, { recursive: true, force: true });
mkdirSync(mailTarget, { recursive: true });
cpSync(exported, mailTarget, { recursive: true });
await build({
  entryPoints: ["desktop/relay-worker.mjs"],
  outfile: "desktop/bundle/relay-worker.cjs",
  platform: "node",
  format: "cjs",
  target: "node22",
  bundle: true,
  packages: "external",
  logLevel: "info"
});
console.log("Quantic Mail local prêt : interface statique + relais autonome embarqué.");
