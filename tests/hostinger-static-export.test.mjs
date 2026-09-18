import assert from "node:assert/strict";
import fs from "node:fs";

const config=fs.readFileSync("next.config.ts","utf8");
assert.match(config,/QUANTIC_STATIC_EXPORT/);
assert.match(config,/output:\s*["']export["']/);
assert.match(config,/basePath:\s*["']\/mail["']/);
assert.match(config,/trailingSlash:\s*true/);

const pkg=JSON.parse(fs.readFileSync("package.json","utf8"));
assert.ok(pkg.scripts["build:hostinger"],"Hostinger build script must exist");
assert.match(pkg.scripts["build:hostinger"],/QUANTIC_STATIC_EXPORT=1|cross-env/);

console.log(JSON.stringify({ok:true,contract:"hostinger-static-export"}));
