import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

test("QuanticMail keeps a single global nav owner and mobile overflow guards", async () => {
  const [layout, app, css] = await Promise.all([
    readFile(new URL("../app/layout.tsx", import.meta.url), "utf8"),
    readFile(new URL("../components/quantic-network-v11-app.tsx", import.meta.url), "utf8"),
    readFile(new URL("../app/quantic.css", import.meta.url), "utf8"),
  ]);

  assert.match(layout, /<QuanticGlobalNav\s*\/>/, "layout.tsx must own the global navigation");
  assert.doesNotMatch(app, /<QuanticGlobalNav\s*\/>/, "V1.3 app must not render a duplicate global navigation");
  assert.doesNotMatch(app, /import\s*\{\s*QuanticGlobalNav\s*\}/, "V1.3 app must not import the global navigation");

  for (const required of [
    "overflow-x:hidden",
    ".qn-address{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}",
    "@media(max-width:760px)",
    "grid-template-columns:minmax(0,1fr)",
    ".qn-sidebar{",
  ]) {
    assert.ok(css.includes(required), "Missing mobile stability rule: " + required);
  }
});
