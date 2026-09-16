import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

test("/devices renders the V1.1 pairing app", async () => {
  const source = await readFile(new URL("../app/devices/page.tsx", import.meta.url), "utf8");
  assert.match(source, /DevicesV11App/);
  assert.doesNotMatch(source, /DevicesV1App\b/);
});
