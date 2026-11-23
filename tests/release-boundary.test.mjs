import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { inspectReleaseBoundary } from '../scripts/assert-release-boundary.mjs';

const document=JSON.parse(readFileSync(fileURLToPath(
  new URL('../security/release-boundary.json',import.meta.url)),'utf8'));
const copy=()=>structuredClone(document);

test('legacy Web and legacy desktop may publish without sensitive claims',()=>{
  for(const mode of ['--assert-web','--assert-desktop']){
    const result=inspectReleaseBoundary(copy(),mode);
    assert.equal(result.accepted,true);
    assert.equal(result.declaredSensitiveCapabilities,false);
    assert.match(result.policySha256,/^[0-9a-f]{64}$/);
  }
});
test('future sensitive release cannot use local JSON policy as authorization',()=>{
  assert.throws(()=>inspectReleaseBoundary(copy(),'--assert-sensitive'),/forbidden/);
});
test('setting any of six unproven capabilities forbids legacy publication',()=>{
  for(const field of Object.keys(document.capabilities)){
    const d=copy();
    d.capabilities[field]=true;
    assert.throws(()=>inspectReleaseBoundary(d,'--assert-web'),/disabled/);
    assert.throws(()=>inspectReleaseBoundary(d,'--assert-desktop'),/disabled/);
  }
});
test('certified claim and invalid declaration formats rejected',()=>{
  for(const [key,value] of [['releaseClass','certified'],['independentAssurance','APPROVED'],['securityAudit','COMPLETE']]){
    const d=copy();
    d[key]=value;
    assert.throws(()=>inspectReleaseBoundary(d,'--check'),/Invalid/);
  }
  const d=copy();d.extra=true;
  assert.throws(()=>inspectReleaseBoundary(d,'--check'),/Invalid/);
});
test('unexpected runtime environment switches are rejected',()=>{
  const key='QUANTIC_ENABLE_REAL_PAYMENTS',prior=process.env[key];
  try{
    process.env[key]='true';
    assert.throws(()=>inspectReleaseBoundary(copy(),'--assert-web'),/switch forbidden/);
  } finally {
    if (prior===undefined) delete process.env[key];
    else process.env[key]=prior;
  }
});
test('status remains explicitly experimental and requires protected branch rules',()=>{
  const result=inspectReleaseBoundary(copy(),'--check');
  assert.equal(result.auditStatus,'UNVERIFIED');
  assert.match(result.note,/protected branch/);
  assert.throws(()=>inspectReleaseBoundary(copy(),'--unexpected'),/Unknown/);
});
