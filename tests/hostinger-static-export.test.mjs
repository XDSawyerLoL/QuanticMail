import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import test from "node:test";

test("legacy publication and normal runtime scripts cannot restart the Web product", () => {
  const pkg = JSON.parse(readFileSync("package.json", "utf8"));
  for (const name of ["dev","build","start","relay:start","relay:dev","build:hostinger","relay:hostinger","relay:smoke","desktop:start","desktop:dist"]) {
    assert.equal(pkg.scripts[name], "node scripts/legacy-retired.mjs", name);
  }
  const result = spawnSync(process.execPath, ["scripts/legacy-retired.mjs"], { encoding: "utf8" });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /retired/);
  for (const path of [".github/workflows/publish-hostinger-dist.yml", ".github/workflows/desktop-release.yml"]) {
    const workflow = readFileSync(path, "utf8");
    assert.match(workflow, /permissions: \{\}/);
    assert.doesNotMatch(workflow, /push:|gh release|git push|npm run|actions\/checkout/);
  }
});

test("direct legacy entry points refuse execution even when bypassing npm", () => {
  for (const path of ["desktop/main.cjs", "scripts/build-hostinger-static.mjs", "scripts/smoke-hostinger-relay.mjs", "standalone-relay/main.ts", "standalone-relay/hostinger-main.ts"]) {
    const result = spawnSync(process.execPath, ["--experimental-transform-types", path], { encoding: "utf8", timeout: 5000 });
    assert.equal(result.status, 1, path + ": " + result.stderr);
    assert.match(result.stderr, /legacy runtime retired/, path);
  }
  const result = spawnSync("bash", ["scripts/bootstrap-mail-vps.sh"], { encoding: "utf8", timeout: 5000 });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /legacy runtime retired/);
  assert.match(readFileSync("next.config.ts", "utf8"), /throw new Error/);
});
