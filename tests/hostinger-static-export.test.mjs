import assert from "node:assert/strict";
import fs from "node:fs";

const config=fs.readFileSync("next.config.ts","utf8");
assert.match(config,/QUANTIC_STATIC_EXPORT/);
assert.match(config,/output:\s*["']export["']/);
assert.match(config,/basePath:\s*["']\/mail["']/);
assert.match(config,/trailingSlash:\s*true/);

const pkg=JSON.parse(fs.readFileSync("package.json","utf8"));
assert.equal(pkg.version,"1.3.0");
assert.equal(pkg.scripts["build:hostinger"],"node scripts/build-hostinger-static.mjs");

const script=fs.readFileSync("scripts/build-hostinger-static.mjs","utf8");
assert.match(script,/app[\\/]api|app",\s*"api"/);
assert.match(script,/cpSync|copyFileSync/);
assert.match(script,/next/);
assert.match(script,/out/);

const publish=fs.readFileSync(".github/workflows/publish-hostinger-dist.yml","utf8");
assert.match(publish,/https:\/\/quantic-hostinger-relay\.invalid/);
assert.match(publish,/NEXT_PUBLIC_QUANTIC_BOOTSTRAPS/);
assert.match(publish,/grep -R -q/);

console.log(JSON.stringify({ok:true,contract:"hostinger-static-export"}));
