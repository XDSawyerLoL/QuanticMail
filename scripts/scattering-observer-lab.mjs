#!/usr/bin/env node
// Diagnostic-only synthetic batch source attribution; no cryptographic claims.
import {compareObserverScenarios} from '../lib/quantic/scattering-batch-observer-lab.mjs';
const options = {};
for (const raw of process.argv.slice(2)) {
  const match = /^--(trials|seed|ticks|users)=(\d+)$/.exec(raw);
  if (!match) {
    console.error('Usage: node scripts/scattering-observer-lab.mjs [--trials=24] [--seed=20261123] [--ticks=6400] [--users=12]');
    process.exitCode = 2;
    break;
  }
  options[match[1]] = Number(match[2]);
}
if (!process.exitCode) {
  try { console.log(JSON.stringify(compareObserverScenarios(options), null, 2)); }
  catch (error) {console.error(error.message); process.exitCode = 2;}
}
