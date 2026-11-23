import assert from 'node:assert/strict';
import test from 'node:test';
import {
  ALPHABET_SIZE, binMetadata, countLabMetadata,
  conditionalIndistinguishabilityBound,
} from '../labs/quantic-native/scattering/statistical-bound.mjs';

function all(n, index) {
  const x=Array(ALPHABET_SIZE).fill(0);
  x[index]=n;
  return x;
}
test('exact finite-alphabet upper bound narrows with many equal IID samples', () => {
  const x=conditionalIndistinguishabilityBound({real:all(1_000_000,9),cover:all(1_000_000,9)});
  assert.equal(x.empiricalTotalVariation,0);
  assert.ok(x.optimalBalancedSinglePacketAccuracyUpperBound > 0.5);
  assert.ok(x.optimalBalancedSinglePacketAccuracyUpperBound < 0.525);
  assert.equal(x.endToEndAnonymityProven,false);
  assert.equal(x.releaseAuthorized,false);
});
test('disjoint synthetic populations have total variation 1', () => {
  const x=conditionalIndistinguishabilityBound({real:all(1000,1),cover:all(1000,2)});
  assert.equal(x.empiricalTotalVariation,1);
  assert.equal(x.totalVariationUpperConfidenceBound,1);
  assert.equal(x.optimalBalancedSinglePacketAccuracyUpperBound,1);
});
test('small samples produce a trivial bound and cannot establish anonymity', () => {
  const x=conditionalIndistinguishabilityBound({real:all(100,9),cover:all(100,9)});
  assert.equal(x.totalVariationUpperConfidenceBound,1);
  assert.equal(x.endToEndAnonymityProven,false);
});
test('binning uses only fixed metadata and rejects sensitive fields', () => {
  assert.equal(binMetadata({packetBytes:168,gapMs:20,direction:'out'}),13);
  assert.notEqual(binMetadata({packetBytes:168,gapMs:20,direction:'out'}),
                  binMetadata({packetBytes:169,gapMs:20,direction:'out'}));
  assert.throws(() => binMetadata({packetBytes:168,gapMs:20,direction:'out',recipient:'bob'}),/Invalid/);
  assert.throws(() => binMetadata({packetBytes:168,gapMs:-1,direction:'out'}),/Invalid/);
  const counts=countLabMetadata([
    {kind:'real',packetBytes:168,gapMs:20,direction:'out'},
    {kind:'cover',packetBytes:169,gapMs:20,direction:'out'},
  ]);
  assert.equal(counts.real.reduce((a,b)=>a+b,0),1);
  assert.equal(counts.cover.reduce((a,b)=>a+b,0),1);
  assert.throws(()=>countLabMetadata([{kind:'real',packetBytes:168,gapMs:20,direction:'out',ciphertext:'private'}]),/sensitive/);
});
test('bad counts, options and insufficient observations fail closed', () => {
  assert.throws(()=>conditionalIndistinguishabilityBound({real:[],cover:[]}),/24-bin/);
  assert.throws(()=>conditionalIndistinguishabilityBound({real:all(100,1),cover:all(99,1)}),/100 independent/);
  assert.throws(()=>conditionalIndistinguishabilityBound({real:all(100,1),cover:all(100,1)},{alpha:0}),/confidence alpha/);
  assert.throws(()=>conditionalIndistinguishabilityBound({real:all(100,1),cover:all(100,1),userid:'private'}),/Exactly/);
});
