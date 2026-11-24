import test from 'node:test';
import assert from 'node:assert/strict';
import {parseTcpdumpLines,analyzeNamespacePair} from '../lib/quantic/scattering-netns-evidence.mjs';

const cap = (gap=0.02, port=49001) => [
  '1763982000.000000 IP 10.250.31.1.55001 > 10.250.31.2.'+port+': UDP, length 168',
  (1763982000+gap).toFixed(6)+' IP 10.250.31.1.55001 > 10.250.31.2.'+port+': UDP, length 168',
  (1763982000+gap*2).toFixed(6)+' IP 10.250.31.1.55001 > 10.250.31.2.'+port+': UDP, length 168',
].join('\n');
const snd = mode => JSON.stringify({mode,report:'QS V7.1 NATIVE | planned=3 sent=3 missed=0 (0.000%)'})+'\n';
const rx = () => JSON.stringify({mode:'physical-cover-receive',received:3,malformed:0})+'\n';
const input = () => ({
  cover:{capture:cap(),sender:snd('physical-cover-send'),receiver:rx()},
  synthetic:{capture:cap(.021),sender:snd('physical-synthetic-send'),receiver:rx()},
});
test('extract passive UDP packet timestamps without exposing address fields',()=>{
  const r=parseTcpdumpLines(cap());
  assert.equal(r.times.length,3);
  assert.deepEqual(r.lengths,[168,168,168]);
  assert.equal(Object.hasOwn(r,'ip'),false);
});
test('compare cover and synthetic packet count and timing across veth link',()=>{
  const r=analyzeNamespacePair(input());
  assert.equal(r.twoPhysicalHostsTested,false);
  assert.equal(r.independentPassiveCaptureProcess,true);
  assert.equal(r.conditions.cover.passive.received,3);
  assert.equal(r.conditions.synthetic.sender.sent,3);
  assert.equal(r.deltas.capturedBusyMinusCover,0);
  assert.ok(r.deltas.p95GapBusyMinusCoverMs>=.9);
});
test('refuse missing frames, truncated counters and invalid packet lengths',()=>{
  let x=input();x.cover.capture='';
  assert.throws(()=>analyzeNamespacePair(x));
  x=input();x.synthetic.sender='{"report":"bad"}';
  assert.throws(()=>analyzeNamespacePair(x));
  x=input();x.synthetic.capture=x.synthetic.capture.replace(/length 168/g,'length 150');
  assert.throws(()=>analyzeNamespacePair(x));
});
test('refuse receiver count above native sender count',()=>{
  const x=input();x.synthetic.receiver=JSON.stringify({mode:'physical-cover-receive',received:4,malformed:0});
  assert.throws(()=>analyzeNamespacePair(x));
});
