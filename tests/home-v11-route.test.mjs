import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

test("home renders the V1.1 network client", async () => {
  const source = await readFile(new URL("../app/page.tsx", import.meta.url), "utf8");
  assert.match(source, /QuanticNetworkV11App/);
  assert.doesNotMatch(source, /QuanticNetworkV1App\b/);
});
