#!/usr/bin/env node
// Produce an explicit NSIS uninstall inventory from the exact payload of this build.
// Never generate a recursive deletion: unrecognized files and vaults must survive.
import { readdirSync, lstatSync, writeFileSync } from "node:fs";
import path from "node:path";

const [rootArg, outputArg] = process.argv.slice(2);
if (!rootArg || !outputArg) {
  throw new Error("Usage: node build-alpha-uninstall-inventory.mjs PACKAGE_DIR OUTPUT_NSH");
}
const root = path.resolve(rootArg);
const files = [];
const directories = [];
const safeComponent = /^[A-Za-z0-9._+()@ -]+$/;
function walk(dir, prefix = "") {
  for (const entry of readdirSync(dir, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name, "en"))) {
    if (!safeComponent.test(entry.name) || entry.name === "." || entry.name === ".." || entry.name.endsWith(".") || entry.name.endsWith(" ")) {
      throw new Error(`Unsupported NSIS payload filename: ${entry.name}`);
    }
    const relative = prefix ? `${prefix}\\${entry.name}` : entry.name;
    const absolute = path.join(dir, entry.name);
    const stat = lstatSync(absolute);
    if (stat.isSymbolicLink()) throw new Error(`Refusing a symbolic link in payload: ${relative}`);
    if (stat.isDirectory()) {
      directories.push(relative);
      walk(absolute, relative);
    } else if (stat.isFile()) {
      files.push(relative);
    } else {
      throw new Error(`Unsupported payload entry: ${relative}`);
    }
  }
}
walk(root);
if (files.length === 0) throw new Error("Cannot create an empty uninstaller inventory");

const lines = [
  "; Generated at CI build time from the exact payload, never edit manually.",
  "; Guard every directory against junctions/reparse points before deleting anything.",
];
const directoryPaths = [
  "$LOCALAPPDATA\\QuanticSillage",
  "$INSTDIR",
  "$INSTDIR\\app",
  ...directories.map(d => `$INSTDIR\\app\\${d}`),
];
for (const [i, p] of directoryPaths.entries()) {
  lines.push(
    ` IfFileExists "${p}\\." 0 safe_reparse_${i}`,
    ` System::Call 'kernel32::GetFileAttributesW(w "${p}") i .r0'`,
    " IntOp $1 $0 & 0x400",
    ` IntCmp $1 0 safe_reparse_${i}`,
    " SetErrorLevel 2",
    ' Abort "Unsafe reparse point in installation directory. No files removed."',
    ` safe_reparse_${i}:`
  );
}
lines.push("; Only delete files packaged by this exact build, never unknown entries.");
for (const f of files) lines.push(` Delete "$INSTDIR\\app\\${f}"`);
lines.push("; Non-recursive directory removal preserves any unknown files.");
for (const d of directories.sort((a, b) => b.split("\\").length - a.split("\\").length || b.localeCompare(a))) {
  lines.push(` RMDir "$INSTDIR\\app\\${d}"`);
}
lines.push(' RMDir "$INSTDIR\\app"');
writeFileSync(path.resolve(outputArg), lines.join("\n") + "\n", { encoding: "utf8", flag: "w" });
console.log(`Generated ${files.length} explicit uninstall deletions and ${directories.length} directories`);
