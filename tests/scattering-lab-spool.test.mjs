import test from "node:test";
import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { mkdtemp, writeFile, readFile, readdir, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { validateLabSpool, publishLabSpool } from "../lib/quantic-network/scattering-lab-spool.mjs";
function fixture(n=8) {
  const h=Buffer.alloc(16); h.write("QS69Q001"); h.writeUInt32BE(n,8); h.writeUInt32BE(168,12);
  const body=Buffer.concat([h,randomBytes(n*168)]);
  return Buffer.concat([body,createHash("sha256").update(body).digest()]);
}
test("valid format and mutations, truncations and invalid frame count rejected",()=>{
  const b=fixture();
  assert.equal(validateLabSpool(b),8);
  for(const offset of [0,8,12,16,b.length-1]) {
    const invalid=Buffer.from(b); invalid[offset]^=1;
    assert.throws(()=>validateLabSpool(invalid));
  }
  assert.throws(()=>validateLabSpool(b.subarray(0,-1)));
  assert.throws(()=>validateLabSpool(Buffer.alloc(16+30001*168+32)));
});
test("explicit lab opt-in; identical spool; no temporary residue; damaged batch rejected",async()=>{
  const root=await mkdtemp(join(tmpdir(),"qs-lab-"));
  try {
    const source=join(root,"synthetic.qs69");
    const b=fixture(); await writeFile(source,b);
    await assert.rejects(publishLabSpool({source,queueRoot:root}),/opt-in/);
    const result=await publishLabSpool({labOnly:true,source,queueRoot:root});
    assert.equal(result.productionEnabled,false);
    assert.equal(result.frames,8);
    assert.deepEqual(await readFile(result.path),b);
    const corrupted=Buffer.from(b);corrupted[20]^=1;await writeFile(source,corrupted);
    await assert.rejects(publishLabSpool({labOnly:true,source,queueRoot:root}),/damaged/);
    assert.equal((await readdir(join(root,"scattering-lab"))).length,1);
  } finally { await rm(root,{recursive:true,force:true}); }
});
