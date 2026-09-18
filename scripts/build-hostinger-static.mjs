import { cpSync, existsSync, mkdtempSync, rmSync, symlinkSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { dirname, join, relative, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const work = mkdtempSync(join(tmpdir(), "quanticmail-hostinger-"));
const output = join(root, "out");
const apiRoot = join(root, "app", "api");
const excludedRoots = [
  join(root, ".git"),
  join(root, ".next"),
  join(root, "node_modules"),
  join(root, "out"),
];

function isInside(parent, candidate) {
  const rel = relative(parent, candidate);
  return rel === "" || (!rel.startsWith("..") && !rel.startsWith("/"));
}

function shouldCopy(source) {
  if (isInside(apiRoot, source)) return false;
  return !excludedRoots.some((excluded) => isInside(excluded, source));
}

try {
  cpSync(root, work, {
    recursive: true,
    filter: shouldCopy,
  });

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
