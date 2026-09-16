import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

test("/devices/files keeps the V1 file-pairing fallback", async () => {
  const source = await readFile(new URL("../app/devices/files/page.tsx", import.meta.url), "utf8");
  assert.match(source, /DevicesV1App/);
});
