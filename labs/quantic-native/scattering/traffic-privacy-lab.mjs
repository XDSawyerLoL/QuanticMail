/**
 * Experimental traffic distinguisher for LOCAL LAB metadata only.
 * This is a measurement tool, not a cryptographic primitive or anonymity proof.
 * Threat model: packet length, inter-arrival gap and direction are observable.
 */
import { readFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';

const FIELDS = new Set(['kind', 'packetBytes', 'gapMs', 'direction']);
const MAX_RECORDS = 100_000;
function validate(row, index) {
  if (!row || typeof row !== 'object' || Array.isArray(row)) throw new TypeError('Invalid row ' + index);
  if (Object.keys(row).some(k => !FIELDS.has(k))) {
    throw new TypeError('Disallowed fields: no payloads, identities or addresses (' + index + ')');
  }
  if (row.kind !== 'real' && row.kind !== 'cover') throw new TypeError('Invalid kind ' + index);
  if (!Number.isInteger(row.packetBytes) || row.packetBytes < 1 || row.packetBytes > 65535) {
    throw new RangeError('Invalid packetBytes ' + index);
  }
  if (!Number.isFinite(row.gapMs) || row.gapMs < 0 || row.gapMs > 3600000) {
    throw new RangeError('Invalid gapMs ' + index);
  }
  if (row.direction !== 'in' && row.direction !== 'out') throw new TypeError('Invalid direction ' + index);
  return row;
}
function bucket(gap) {
  for (const cap of [1, 2, 5, 10, 20, 50, 100, 200, 500, 1000, 5000, 10000, 60000]) {
    if (gap < cap) return String(cap);
  }
  return 'big';
}
function feature(row) {
  // Keep exact public packet length: one byte may form a side-channel.
  return row.packetBytes + '|' + bucket(row.gapMs) + '|' + row.direction;
}
function randomFactory(seed) {
  let s = seed >>> 0;
  return () => {
    s += 0x6D2B79F5;
    let t = s;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
function shuffled(items, random) {
  const out = [...items];
  for (let i = out.length - 1; i > 0; i--) {
    const j = Math.floor(random() * (i + 1));
    [out[i], out[j]] = [out[j], out[i]];
  }
  return out;
}
function frequencies(items) {
  const map = new Map();
  for (const item of items) {
    const key = feature(item);
    map.set(key, (map.get(key) || 0) + 1);
  }
  return map;
}
function accuracy(predictions, actual) {
  let count = 0;
  for (let i = 0; i < predictions.length; i++) if (predictions[i] === actual[i]) count++;
  return count / predictions.length;
}

/**
 * A fixed feature-classifier is trained on stratified 75% samples, tested on
 * independent equal-class 25% holdout, then calibrated with label permutations.
 * A high p-value does NOT establish anonymity; global observers may be stronger.
 */
export function evaluateTrafficLeakage(records, options = {}) {
  if (!Array.isArray(records) || records.length > MAX_RECORDS) {
    throw new RangeError('At most 100000 lab metadata records accepted');
  }
  const seed = options.seed ?? 20261123;
  const permutations = options.permutations ?? 999;
  if (!Number.isSafeInteger(seed) || seed < 0 || seed > 0xffffffff) throw new RangeError('Invalid seed');
  if (!Number.isSafeInteger(permutations) || permutations < 99 || permutations > 9999) {
    throw new RangeError('Permutations must be in 99..9999');
  }
  const groups = { real: [], cover: [] };
  records.forEach((raw, i) => {
    const row = validate(raw, i);
    groups[row.kind].push(row);
  });
  if (groups.real.length < 32 || groups.cover.length < 32) {
    throw new RangeError('At least 32 real and 32 cover observations required');
  }
  const random = randomFactory(seed); // reproducible statistics, NEVER crypto
  const real = shuffled(groups.real, random);
  const cover = shuffled(groups.cover, random);
  const holdout = Math.min(Math.floor(real.length / 4), Math.floor(cover.length / 4));
  const trainReal = real.slice(holdout);
  const trainCover = cover.slice(holdout);
  const test = [...real.slice(0, holdout), ...cover.slice(0, holdout)];
  const realFreq = frequencies(trainReal);
  const coverFreq = frequencies(trainCover);
  const predictions = test.map(row => {
    const key = feature(row);
    const r = (realFreq.get(key) || 0) / trainReal.length;
    const c = (coverFreq.get(key) || 0) / trainCover.length;
    return r > c ? 'real' : 'cover';
  });
  const labels = test.map(row => row.kind);
  const balancedAccuracy = accuracy(predictions, labels);
  const deviation = Math.abs(balancedAccuracy - 0.5);
  let extreme = 0;
  for (let i = 0; i < permutations; i++) {
    const permuted = shuffled(labels, random);
    if (Math.abs(accuracy(predictions, permuted) - 0.5) >= deviation - 1e-12) extreme++;
  }
  const pValue = (extreme + 1) / (permutations + 1);
  return {
    experiment: 'quantic-scattering-observational-leakage-v1',
    threatModel: 'passive-size-timing-direction-only',
    seed,
    permutations,
    train: { real: trainReal.length, cover: trainCover.length },
    test: { real: holdout, cover: holdout },
    balancedAccuracy,
    truePositiveRate: predictions.slice(0, holdout).filter(k => k === 'real').length / holdout,
    trueNegativeRate: predictions.slice(holdout).filter(k => k === 'cover').length / holdout,
    absoluteDeviationFromChance: deviation,
    permutationPValue: pValue,
    potentialLeakageDetected: deviation >= 0.1 && pValue < 0.05,
    conclusion: 'Experimental metadata classifier only; not an anonymity proof or a production security gate.',
  };
}
async function main(args) {
  if (args.length !== 2 || args[0] !== '--input') {
    throw new Error('Usage: node traffic-privacy-lab.mjs --input path/to/metadata.json');
  }
  const contents = await readFile(args[1], 'utf8');
  if (Buffer.byteLength(contents, 'utf8') > 16 * 1024 * 1024) throw new Error('Input too large');
  console.log(JSON.stringify(evaluateTrafficLeakage(JSON.parse(contents)), null, 2));
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main(process.argv.slice(2)).catch(error => {
    console.error('Scattering privacy lab error: ' + error.message);
    process.exitCode = 1;
  });
}
