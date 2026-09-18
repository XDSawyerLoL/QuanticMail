import { cpSync, existsSync, mkdirSync, rmSync, symlinkSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join, relative, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const work = join(root, ".hostinger-static-build");
const output = join(root, "out");
const apiRoot = join(root, "app", "api");

function shouldCopy(source) {
  const rel = relative(apiRoot, source);
  return rel.startsWith("..") || rel === "" ? source !== apiRoot : false;
}

rmSync(work, { recursive: true, force: true });
mkdirSync(work, { recursive: true });

const entries = [
  "app",
  "components",
  "lib",
  "public",
  "instrumentation-client.ts",
  "next.config.ts",
  "next-env.d.ts",
  "package.json",
  "tsconfig.json",
];

try {
  for (const entry of entries) {
    const source = join(root, entry);
    if (!existsSync(source)) continue;
    cpSync(source, join(work, entry), {
      recursive: true,
      filter: shouldCopy,
    });
  }

  symlinkSync(join(root, "node_modules"), join(work, "node_modules"), "dir");

  const nextBin = require.resolve("next/dist/bin/next");
  const build = spawnSync(process.execPath, [nextBin, "build"], {
    cwd: work,
    env: { ...process.env, QUANTIC_STATIC_EXPORT: "1" },
    stdio: "inherit",
  });
  if (build.status !== 0) {
    process.exitCode = build.status ?? 1;
    throw new Error("Le build statique Hostinger de Quantic Mail a échoué.");
  }

  const built = join(work, "out");
  if (!existsSync(join(built, "index.html"))) {
    throw new Error("Le build Hostinger n'a pas produit out/index.html.");
  }

  rmSync(output, { recursive: true, force: true });
  cpSync(built, output, { recursive: true });
  console.log("Quantic Mail Hostinger export prêt dans ./out (API Next exclues du bundle statique).");
} finally {
  rmSync(work, { recursive: true, force: true });
}
