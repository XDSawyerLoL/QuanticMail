import assert from 'node:assert/strict';
import test from 'node:test';
import {
  activeSideChannel, compromiseStudy, deliveryStudy,
  runStudy, simulateCompromise, validateConfig,
} from '../labs/quantic-native/scattering/scattering-adaptive-v07.mjs';

test('rejects invalid models and unknown configuration fields', () => {
  assert.throws(() => validateConfig({threshold:6}), /threshold/);
  assert.throws(() => validateConfig({relays:2}), /relays/);
  assert.throws(() => validateConfig({payload:'secret'}), /Unexpected/);
  assert.throws(() => simulateCompromise('unknown'), /Unknown/);
  assert.throws(() => validateConfig({iterations:0}), /iterations/);
});

test('moving locations without refreshing does not invalidate captured shares', () => {
  const study=compromiseStudy({iterations:500,epochs:12});
  assert.ok(study.static.observedCompromiseFrequency>0.8);
  assert.ok(study['move-only'].observedCompromiseFrequency>0.8);
});

test('idealized proactive refresh blocks cross-epoch accumulation if fewer than threshold relays are lost', () => {
  const study=compromiseStudy({iterations:500,epochs:12,compromisesPerEpoch:2});
  assert.equal(study.refresh.successes,0);
  assert.equal(study['masked-adaptive'].successes,0);
});

test('an adversary accessing threshold shares in an epoch still wins', () => {
  for(const scheme of ['static','move-only','refresh','masked-adaptive']) {
    assert.equal(simulateCompromise(scheme,{threshold:3,compromisesPerEpoch:3,epochs:1},18,true),true);
  }
});

test('immediate intrusion-triggered network changes leak; masked schedule does not in this toy model', () => {
  assert.equal(activeSideChannel('move-only').balancedAccuracy,1);
  assert.equal(activeSideChannel('masked-adaptive').balancedAccuracy,0.5);
  assert.equal(activeSideChannel('masked-adaptive').metadataIdenticalByConstruction,true);
});

test('burst-loss study compares geometry against uniform and random with fixed frame budget', () => {
  const rates=deliveryStudy({iterations:500,burstLength:10});
  assert.deepEqual(Object.keys(rates),['uniform','random','geometry']);
  for(const item of Object.values(rates)) {
    assert.ok(item.successRate>=0&&item.successRate<=1);
    assert.equal(item.trials,500);
    assert.equal(item.wilson95.length,2);
  }
});

test('results are deterministic, refuse to claim anonymity, and omit secret data', () => {
  const a=runStudy({iterations:200,seed:99});
  assert.deepEqual(a,runStudy({iterations:200,seed:99}));
  assert.equal(a.confidentialityProven,false);
  assert.equal(a.securityLevel9999999Proven,false);
  assert.equal(a.releaseAuthorized,false);
  assert.ok(!/ciphertext|privateKey|identityAddress/.test(JSON.stringify(a)));
});
