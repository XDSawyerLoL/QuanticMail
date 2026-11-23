/**
 * Quantic Scattering V0.7: an OFFLINE, synthetic, non-cryptographic threat lab.
 * Model only. No network, key, identity, private data, or production imports.
 * Scenario: n-of-N shares at distinct relays; adversary compromises up to c
 * relays per epoch and retains all captured material unless it is refreshed.
 *
 * Key caveat: simulated refresh assumes old shares cannot combine with shares
 * from another epoch. It does NOT implement secure proactive secret sharing,
 * secure erasure, or authenticate any real relay.
 */
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';

export const STRATEGIES = Object.freeze(['static', 'move-only', 'refresh', 'masked-adaptive']);
export const TIMING = Object.freeze(['uniform', 'random', 'geometry']);

function rng(seed) {
  if (!Number.isSafeInteger(seed) || seed < 0 || seed > 0xffffffff) throw new TypeError('Invalid lab seed');
  let s = seed >>> 0;
  return () => {
    s += 0x6d2b79f5;
    let t = s;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
function sampleUnique(count, max, random) {
  const entries = Array.from({length:max}, (_, i) => i);
  for (let i=0; i<count; i++) {
    const j = i + Math.floor(random()*(max-i));
    [entries[i], entries[j]] = [entries[j], entries[i]];
  }
  return entries.slice(0, count);
}
function requireInt(value, min, max, key) {
  if (!Number.isSafeInteger(value) || value < min || value > max) throw new RangeError('Invalid '+key);
}
export function validateConfig(input = {}) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new TypeError('Invalid configuration');
  const keys = ['seed','iterations','epochs','relays','shares','threshold','compromisesPerEpoch','burstLength'];
  if (Object.keys(input).some(k => !keys.includes(k))) throw new TypeError('Unexpected configuration key');
  const c = {seed:20261123, iterations:2000, epochs:8, relays:10, shares:5,
    threshold:3, compromisesPerEpoch:2, burstLength:10, ...input};
  requireInt(c.seed, 0, 0xffffffff, 'seed');
  requireInt(c.iterations, 10, 50000, 'iterations');
  requireInt(c.epochs, 1, 100, 'epochs');
  requireInt(c.relays, 3, 100, 'relays');
  requireInt(c.shares, 2, c.relays, 'shares');
  requireInt(c.threshold, 2, c.shares, 'threshold');
  requireInt(c.compromisesPerEpoch, 0, c.relays, 'compromisesPerEpoch');
  requireInt(c.burstLength, 0, 23, 'burstLength');
  return c;
}

export function simulateCompromise(strategy, config = {}, seed = 17, omniscient = false) {
  if (!STRATEGIES.includes(strategy)) throw new TypeError('Unknown strategy');
  const c = validateConfig({iterations:10, ...config});
  const random = rng(seed);
  let locations = sampleUnique(c.shares,c.relays,random);
  const collected = new Set();
  for (let epoch=0;epoch<c.epochs;epoch++) {
    // The abstract share identifier remains usable across epochs for
    // static/move-only. Only refresh/masked-adaptive invalidate old shares.
    if (epoch>0 && (strategy==='refresh' || strategy==='masked-adaptive')) collected.clear();
    const targets = omniscient
      ? locations.slice(0,c.compromisesPerEpoch)
      : Array.from({length:c.compromisesPerEpoch},(_,j)=>(epoch*c.compromisesPerEpoch+j)%c.relays);
    for (const relay of targets) {
      const id = locations.indexOf(relay);
      if (id>=0) collected.add(id);
    }
    if (collected.size>=c.threshold) return true;
    if (strategy==='masked-adaptive') {
      // After an idealized detection, avoid currently compromised relay IDs
      // for the *next* epoch; enough spares are required to fail closed.
      const eligible=Array.from({length:c.relays},(_,i)=>i).filter(i=>!targets.includes(i));
      if (eligible.length<c.shares) throw new Error('Insufficient spare relays for quarantine');
      locations=sampleUnique(c.shares,eligible.length,random).map(i=>eligible[i]);
    } else if (strategy!=='static') locations=sampleUnique(c.shares,c.relays,random);
  }
  return false;
}

function binomialWilson(success, n) {
  const p = success/n;
  const z = 1.959963984540054;
  const denominator=1+z*z/n;
  const middle=(p+z*z/(2*n))/denominator;
  const half=(z/denominator)*Math.sqrt(p*(1-p)/n+z*z/(4*n*n));
  return [Math.max(0,middle-half),Math.min(1,middle+half)];
}
export function compromiseStudy(config = {}) {
  const c=validateConfig(config);
  const result={};
  for (const strategy of STRATEGIES) {
    let successes=0;
    for (let i=0;i<c.iterations;i++) {
      if (simulateCompromise(strategy,c, (c.seed+Math.imul(i+1,0x9e3779b1))>>>0)) successes++;
    }
    result[strategy]={observedCompromiseFrequency:successes/c.iterations,
      successes, trials:c.iterations, wilson95:binomialWilson(successes,c.iterations)};
  }
  return result;
}

// A deterministic 1ms event is observable if an intrusion is immediately
// followed by an extra network action. In the masked design the *network*
// emits identical fixed-cadence cells whether intrusion occurs or not.
// 50% means this single-feature binary distinguisher only guesses the prior.
export function activeSideChannel(strategy) {
  if (!STRATEGIES.includes(strategy)) throw new TypeError('Unknown strategy');
  const observations=[];
  for(let i=0;i<200;i++) {
    const intrusion=i%2===0;
    const eventGapMs=strategy==='move-only' && intrusion ? 1 : 20;
    observations.push({intrusion, packetBytes:168, eventGapMs, direction:'out'});
  }
  const distinct=observations.some(r=>r.eventGapMs!==20);
  const correct=observations.filter(r=>(distinct && r.eventGapMs===1)===r.intrusion).length;
  return {feature:'single eventGapMs', balancedAccuracy:correct/observations.length,
    metadataIdenticalByConstruction:!distinct, physicalNetworkValidated:false};
}

function timeSlots(method, random) {
  if(method==='random') return sampleUnique(10,24,random).sort((a,b)=>a-b);
  if(method==='uniform') return Array.from({length:10},(_,i)=>Math.floor((i+0.5)*24/10));
  const slots=new Set();
  for(let i=0;i<10;i++) {
    let cell=Math.floor((i/9)**1.6*23);
    while(slots.has(cell)) cell=(cell+1)%24;
    slots.add(cell);
  }
  return [...slots].sort((a,b)=>a-b);
}
export function deliveryStudy(config = {}) {
  const c=validateConfig(config);
  const report={};
  for (const method of TIMING) {
    const random=rng(c.seed ^ (method==='uniform'?13:method==='random'?29:51));
    let delivered=0;
    for(let i=0;i<c.iterations;i++) {
      const locations=timeSlots(method,random);
      const lostStart=Math.floor(random()*(24-c.burstLength+1));
      const recovered=new Set();
      for(let packet=0;packet<locations.length;packet++) {
        const slot=locations[packet];
        if (slot < lostStart || slot >= lostStart+c.burstLength) recovered.add(packet%5);
      }
      if(recovered.size>=c.threshold)delivered++;
    }
    report[method]={successRate:delivered/c.iterations,
      successes:delivered, trials:c.iterations, wilson95:binomialWilson(delivered,c.iterations)};
  }
  return report;
}

export function runStudy(config = {}) {
  const c=validateConfig(config);
  return {schema:'quantic-scattering-adaptive-v07-synthetic',
    assumptions:{shares:c.shares,threshold:c.threshold,relays:c.relays,
      perEpochCompromiseLimit:c.compromisesPerEpoch, epochs:c.epochs,
      epochRefreshIsIdealized:true, activeIntrusionDetectionAssumedPerfect:true,
      quarantineAssumedToHaveSpares:true, secureErasureProven:false,
      realCryptographyImplemented:false, lossModel:'single contiguous burst in 24 fixed-size fixed-cadence cells, 2 copies per share',
      burstLength:c.burstLength, observedOnly:['packetBytes','gapMs','direction'],
      networkAddressesAndEndpointMetadataOmitted:true, networkValidated:false},
    sampleCount:c.iterations, compromise:compromiseStudy(c),
    adversaryWithThresholdAccess:Object.fromEntries(STRATEGIES.map(s=>[s,simulateCompromise(s,{...c,epochs:1,compromisesPerEpoch:c.threshold},c.seed,true)])),
    intrusionSideChannel:Object.fromEntries(STRATEGIES.map(s=>[s,activeSideChannel(s)])),
    delivery:deliveryStudy(c),
    deliverySensitivity:Object.fromEntries([6,10,14,18,20].map(n=>[n,deliveryStudy({...c,burstLength:n})])),
    confidentialityProven:false, securityLevel9999999Proven:false, releaseAuthorized:false};
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)) {
  try {
    if (process.argv.length!==2 && (process.argv.length!==4 || process.argv[2]!=='--iterations')) throw Error('Use --iterations N or no arguments');
    const args=process.argv.length===4?{iterations:Number(process.argv[3])}:{};
    console.log(JSON.stringify(runStudy(args),null,2));
  }catch(e){console.error('V0.7 lab refused: '+e.message);process.exitCode=1;}
}
