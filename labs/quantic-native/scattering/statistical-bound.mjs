/**
 * A mathematically valid, distribution-free *conditional* upper confidence
 * bound for an optimal single-packet observer on a FIXED 24-category alphabet.
 *
 * Assumptions: independent IID observations within each class, unbiased
 * sampling, no unknown metadata dimensions, equal class priors. The result
 * does not cover packet sequences, endpoints, network adaptation or active
 * attackers, and is NOT a proof of traffic anonymity.
 *
 * Hoeffding + union bound: for each class X in {real,cover}, k categories,
 * P(any |p_i - pHat_i| > eps_X) <= 2*k*exp(-2*n_X*eps_X^2).
 * Allocate alpha/2 to each class:
 * eps_X = sqrt(log(4*k/alpha)/(2*n_X)).
 * Triangle inequality:
 * TV(P,Q) <= TV(PHat,QHat) + k*(eps_real+eps_cover)/2
 * with confidence >= 1-alpha.
 * For equally likely binary hypotheses, optimal success = (1+TV)/2.
 */
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';

export const ALPHABET_SIZE = 24;
export const BIN_SPEC = 'packetBytes:<168|=168|>168;gapMs:<10|10..49|50..199|>=200;direction:in|out';
const requireSafeCount = n => Number.isSafeInteger(n) && n >= 0;
export function binMetadata(row) {
  if (!row || typeof row !== 'object' || Array.isArray(row) ||
      Object.keys(row).some(k => !['packetBytes', 'gapMs', 'direction'].includes(k)) ||
      !Number.isInteger(row.packetBytes) || row.packetBytes < 1 || row.packetBytes > 65535 ||
      !Number.isFinite(row.gapMs) || row.gapMs < 0 ||
      !['in','out'].includes(row.direction)) {
    throw new Error('Invalid lab-only metadata (no identities, payloads or IPs)');
  }
  const size = row.packetBytes < 168 ? 0 : row.packetBytes === 168 ? 1 : 2;
  const gap = row.gapMs < 10 ? 0 : row.gapMs < 50 ? 1 : row.gapMs < 200 ? 2 : 3;
  return (size * 4 + gap) * 2 + (row.direction === 'out' ? 1 : 0);
}
export function countLabMetadata(records) {
  if (!Array.isArray(records) || records.length > 1_000_000) throw new Error('Invalid lab records');
  const result = {real:Array(ALPHABET_SIZE).fill(0), cover:Array(ALPHABET_SIZE).fill(0)};
  for (const row of records) {
    if (!row || !['real','cover'].includes(row.kind) ||
        Object.keys(row).some(k => !['kind','packetBytes','gapMs','direction'].includes(k))) {
      throw new Error('Invalid trace kind or extra sensitive fields');
    }
    const {kind, ...metadata} = row;
    result[kind][binMetadata(metadata)]++;
  }
  return result;
}
export function conditionalIndistinguishabilityBound(counts, options={}) {
  if (!counts || typeof counts !== 'object' || Array.isArray(counts) ||
      Object.keys(counts).sort().join(',') !== 'cover,real') {
    throw new Error('Exactly real and cover counts are required');
  }
  const alpha = options.alpha ?? 0.05;
  if (!(typeof alpha === 'number' && Number.isFinite(alpha) && alpha >= 0.001 && alpha <= 0.2) ||
      Object.keys(options).some(k => k !== 'alpha')) {
    throw new Error('Invalid confidence alpha');
  }
  for (const label of ['real','cover']) {
    if (!Array.isArray(counts[label]) || counts[label].length !== ALPHABET_SIZE ||
        counts[label].some(n => !requireSafeCount(n))) throw new Error('Invalid 24-bin counts');
  }
  const nReal = counts.real.reduce((a,b)=>a+b,0);
  const nCover = counts.cover.reduce((a,b)=>a+b,0);
  if (!requireSafeCount(nReal) || !requireSafeCount(nCover) || nReal < 100 || nCover < 100) {
    throw new Error('At least 100 independent samples per class required');
  }
  let tv = 0;
  for (let i=0;i<ALPHABET_SIZE;i++) {
    tv += Math.abs(counts.real[i]/nReal - counts.cover[i]/nCover);
  }
  tv /= 2;
  const factor = Math.log(4*ALPHABET_SIZE/alpha);
  const epsilonReal = Math.sqrt(factor/(2*nReal));
  const epsilonCover = Math.sqrt(factor/(2*nCover));
  const upperTV = Math.min(1, tv + ALPHABET_SIZE*(epsilonReal + epsilonCover)/2);
  return {
    schema:'quantic-scattering-iid-24bins-hoeffding-v1',
    bins:BIN_SPEC,
    samples:{real:nReal,cover:nCover},
    confidence:1-alpha,
    empiricalTotalVariation:tv,
    totalVariationUpperConfidenceBound:upperTV,
    optimalBalancedSinglePacketAccuracyUpperBound:(1+upperTV)/2,
    guaranteedOnlyIf:'IID independent samples within each class, unbiased capture, this fixed alphabet, equal prior probabilities, and no other observable features',
    endToEndAnonymityProven:false,
    releaseAuthorized:false,
  };
}
function cli() {
  const args=process.argv.slice(2);
  if (args.length!==2 || args[0]!=='--input') {
    throw new Error('Usage: node statistical-bound.mjs --input lab-aggregate.json');
  }
  const payload=JSON.parse(readFileSync(args[1], 'utf8'));
  console.log(JSON.stringify(conditionalIndistinguishabilityBound(payload),null,2));
}
if (process.argv[1] && resolve(process.argv[1])===fileURLToPath(import.meta.url)) {
  try {cli();} catch(e) {console.error('Statistical bound refused: '+e.message);process.exitCode=1;}
}
