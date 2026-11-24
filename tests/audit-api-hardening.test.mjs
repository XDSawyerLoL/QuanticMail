import test from "node:test";
import assert from "node:assert/strict";
import {readBoundedJson} from "../lib/security/bounded-json.ts";
import {readFile} from "node:fs/promises";
test("bounded JSON accepts valid object and rejects oversized declared length", async()=>{
  assert.deepEqual(await readBoundedJson(new Request("http://localhost",{method:"POST",body:'{"ok":true}'}),32),{ok:true});
  await assert.rejects(readBoundedJson(new Request("http://localhost",{method:"POST",headers:{"content-length":"9000"},body:"{}"}),32),{status:413});
});
test("bounded JSON enforces actual streamed size without content length",async()=>{
  const stream=new ReadableStream({start(c){c.enqueue(new Uint8Array(20));c.enqueue(new Uint8Array(20));c.close();}});
  await assert.rejects(readBoundedJson(new Request("http://localhost",{method:"POST",body:stream,duplex:"half"}),32),{status:413});
});
test("bounded JSON rejects nonobjects and invalid UTF8",async()=>{
  for(const body of ["null","[]","{",new Uint8Array([255])])await assert.rejects(readBoundedJson(new Request("http://localhost",{method:"POST",body}),32),{status:400});
});
test("prekey and pairing routes use authenticated device and current registry",async()=>{
  const pre=await readFile(new URL("../lib/quantic/prekey-relay.ts",import.meta.url),"utf8");
  const pair=await readFile(new URL("../lib/quantic/pairing-relay.ts",import.meta.url),"utf8");
  assert.match(pre,/await activeManifestDevice\(sender.canonicalAddress, sender.deviceId\)/);
  assert.match(pre,/getCurrentManifest\(canonicalAddress\)/);
  assert.match(pair,/getCurrentManifest\(authenticated.canonicalAddress\)/);
  assert.match(pair,/root.deviceId !== authenticated.deviceId/);
});
test("inbound webhook does not log email metadata or raw errors",async()=>{
  const source=await readFile(new URL("../app/api/inbound/resend/route.ts",import.meta.url),"utf8");
  assert.doesNotMatch(source,/email\.(from|to|subject|html|text)|console\.error\([^\n]*,\s*error\)/);
});
