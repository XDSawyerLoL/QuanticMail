import assert from "node:assert/strict";
import fs from "node:fs";

const app=fs.readFileSync("components/quantic-network-v11-app.tsx","utf8");
const css=fs.readFileSync("app/quantic.css","utf8");

assert.match(app,/function QuanticGlobalNav/);
for (const href of ["/vision/","/mail/","/network/","/products/","/quantic/"]) {
  assert.ok(app.includes(`href="${href}"`), `missing global link ${href}`);
}
assert.ok((app.match(/<QuanticGlobalNav \/>/g)||[]).length>=2,"global nav must appear before onboarding and app surfaces");
assert.match(css,/\.qn-global-nav/);
assert.match(css,/\.qn-global-links/);
assert.match(css,/#148cff/);
assert.match(css,/#20d8ff/);
assert.match(css,/#9b5cff/);
assert.match(css,/#ffc74d/);

console.log(JSON.stringify({ok:true,contract:"quanticmail-global-nav"}));
