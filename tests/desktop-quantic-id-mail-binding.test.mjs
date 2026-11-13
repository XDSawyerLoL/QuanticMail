import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  bindMailboxToQuanticId,
  decideQuanticIdMailboxAccess,
} from "../lib/quantic/quantic-id-mail-binding.mjs";

const ID_A = "qid_" + "a".repeat(32);
const ID_B = "qid_" + "b".repeat(32);
const mailbox = Object.freeze({
  address: "example@quantic",
  canonicalAddress: "example~" + "1".repeat(32) + "@quantic",
  privateKey: { kty: "EC", d: "demo-private" },
  signingPrivateKey: { kty: "EC", d: "demo-private-signing" },
});

test("Quantic ID is the single account: no mailbox never creates a second identity silently", () => {
  assert.deepEqual(decideQuanticIdMailboxAccess(null, ID_A), { kind: "mailbox-absent" });
  assert.deepEqual(decideQuanticIdMailboxAccess(null, ""), { kind: "invalid" });
  assert.throws(() => bindMailboxToQuanticId(null, ID_A), /absentes/);
});

test("unbound, existing mailbox requests one explicit local association", () => {
  assert.equal(decideQuanticIdMailboxAccess(mailbox, ID_A).kind, "unbound");
  const linked = bindMailboxToQuanticId(mailbox, ID_A, "2026-11-13T14:00:00.000Z");
  assert.equal(linked.quanticIdKeyId, ID_A);
  assert.equal(linked.canonicalAddress, mailbox.canonicalAddress);
  assert.equal(linked.privateKey, mailbox.privateKey);
  assert.equal(mailbox.quanticIdKeyId, undefined);
  assert.equal(decideQuanticIdMailboxAccess(linked, ID_A).kind, "ready");
});

test("an unlocked second Quantic ID cannot open the first account's mailbox", () => {
  const linked = bindMailboxToQuanticId(mailbox, ID_A);
  assert.equal(decideQuanticIdMailboxAccess(linked, ID_B).kind, "mismatch");
  assert.throws(() => bindMailboxToQuanticId(linked, ID_B), /autre Quantic ID/);
});

test("relinking with the same Quantic ID is idempotent", () => {
  const linked = bindMailboxToQuanticId(mailbox, ID_A);
  assert.equal(bindMailboxToQuanticId(linked, ID_A), linked);
});

test("incomplete or unverified mailbox cannot be silently attached to Quantic ID", () => {
  assert.throws(() => bindMailboxToQuanticId({ ...mailbox, privateKey: null }, ID_A), /complètement/);
  assert.throws(() => bindMailboxToQuanticId({ ...mailbox, signingPrivateKey: null }, ID_A), /complètement/);
  assert.throws(() => bindMailboxToQuanticId(mailbox, "fake-key"), /invalide/);
});

test("linked devices can be associated after a valid root-signed certificate has been installed", () => {
  const secondary = { ...mailbox, signingPrivateKey: undefined, deviceCertificate: { format: "quantic-device-certificate" } };
  assert.equal(bindMailboxToQuanticId(secondary, ID_A).quanticIdKeyId, ID_A);
});

test("Quantic ID access is checked for the entire desktop application, not only the inbox", () => {
  const layout = readFileSync(new URL("../app/layout.tsx", import.meta.url), "utf8");
  const gate = readFileSync(new URL("../components/quantic-id-desktop-gate.tsx", import.meta.url), "utf8");
  const mail = readFileSync(new URL("../components/quantic-network-v11-app.tsx", import.meta.url), "utf8");
  assert.match(layout, /<QuanticIdDesktopGate>/);
  assert.match(gate, /decideQuanticIdMailboxAccess/);
  assert.match(gate, /bindMailboxToQuanticId/);
  assert.match(gate, /verifyUnlockedVault/);
  assert.match(gate, /"mismatch"/);
  assert.match(mail, /quanticIdKeyId: verified.keyId/);
  assert.doesNotMatch(mail, /Quantic ID et boîte mail sont deux clés différentes/);
});
