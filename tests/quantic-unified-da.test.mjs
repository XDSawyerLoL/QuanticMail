import assert from "node:assert/strict";
import fs from "node:fs";

const css=fs.readFileSync("app/quantic.css","utf8");
for (const token of ["#02050b","#148cff","#20d8ff","#9b5cff","#ffc74d"]) {
  assert.ok(css.includes(token), `missing unified Quantic token ${token}`);
}
assert.match(css,/radial-gradient/);
assert.match(css,/prefers-reduced-motion/);
assert.match(css,/\.qn-topbar/);
assert.match(css,/\.qn-card/);
console.log(JSON.stringify({ok:true,contract:"quanticmail-unified-da"}));
