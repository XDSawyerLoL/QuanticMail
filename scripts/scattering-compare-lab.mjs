#!/usr/bin/env node
// Synthetic lab only; produces JSON, never actual traffic or security claims.
import {compareSchedules} from '../lib/quantic/scattering-mix-comparison-lab.mjs';
const options = {};
for (const raw of process.argv.slice(2)) {
  const match = /^--(ticks|seed|arrivalProbability|burstCells|batchTicks|queueLimit|cellsPerTick|tickMs)=(\d+(?:\.\d+)?)$/.exec(raw);
  if (!match) {
    console.error('Usage: node scripts/scattering-compare-lab.mjs [--seed=7] [--arrivalProbability=0.15] [--ticks=12000] [--burstCells=4] [--cellsPerTick=2] [--batchTicks=8] [--tickMs=50] [--queueLimit=512]');
    process.exitCode = 2;
    break;
  }
  options[match[1]] = Number(match[2]);
}
if (!process.exitCode) {
  try {console.log(JSON.stringify(compareSchedules(options), null, 2));}
  catch (err) {console.error(err.message); process.exitCode = 2;}
}
