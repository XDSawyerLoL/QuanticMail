import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

test("QuanticMail V2 keeps the mobile mail-client shell intact", async () => {
  const [app, css] = await Promise.all([
    readFile(new URL("../components/quantic-network-v11-app.tsx", import.meta.url), "utf8"),
    readFile(new URL("../app/quantic.css", import.meta.url), "utf8"),
  ]);

  for (const token of [
    'className="qm-header"',
    'className={"qm-drawer "',
    'className="qm-message-list"',
    'className={"qm-reader "',
    'className="qm-compose-fab"',
    'className="qm-bottom-nav"',
    'className="qm-compose-sheet"',
  ]) {
    assert.ok(app.includes(token), "Missing QuanticMail V2 UI token: " + token);
  }

  assert.ok(app.includes('useState<"all" | "in" | "out">("in")'), "Inbox must remain the default folder");

  for (const rule of [
    "body:has(.qn-mail-app) .qn-global-nav{display:none!important}",
    ".qm-shell{",
    ".qm-message-row{",
    ".qm-compose-layer{",
    "@media(max-width:860px)",
    "@media(max-width:600px)",
    ".qm-bottom-nav{",
  ]) {
    assert.ok(css.includes(rule), "Missing responsive mail rule: " + rule);
  }
});
