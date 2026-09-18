import assert from "node:assert/strict";
import fs from "node:fs";

const nav=fs.readFileSync("components/quantic-global-nav.tsx","utf8");
const layout=fs.readFileSync("app/layout.tsx","utf8");
const app=fs.readFileSync("components/quantic-network-v11-app.tsx","utf8");
const css=fs.readFileSync("app/quantic.css","utf8");

assert.match(nav,/function QuanticGlobalNav/);
assert.ok(nav.includes("mediumorchid-badger-314305.hostingersite.com"),"global nav must target the Hostinger portal root");
for (const href of ["/vision/","/mail/","/network/","/products/","/quantic/"]) {
  assert.ok(nav.includes(href), `missing global link ${href}`);
}
assert.equal((layout.match(/<QuanticGlobalNav \/>/g)||[]).length,1,"layout must own exactly one global nav");
assert.equal((app.match(/<QuanticGlobalNav \/>/g)||[]).length,0,"mail app must not duplicate the global nav");
assert.equal(app.includes('import { QuanticGlobalNav }'),false,"mail app must not import the global nav");

for (const path of [
  "app/network/page.tsx",
  "app/vault/page.tsx",
  "app/devices/page.tsx",
  "app/devices/files/page.tsx",
]) {
  const page=fs.readFileSync(path,"utf8");
  assert.equal(page.includes("QuanticGlobalNav"),false,`page must rely on layout nav: ${path}`);
}

assert.match(css,/\.qn-global-nav/);
assert.match(css,/\.qn-global-links/);
for (const token of ["#148cff","#20d8ff","#9b5cff","#ffc74d"]) {
  assert.ok(css.includes(token), `missing Quantic palette token ${token}`);
}

console.log(JSON.stringify({ok:true,contract:"quanticmail-global-nav-single-owner"}));
