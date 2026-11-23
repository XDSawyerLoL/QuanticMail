/**
 * Scattering V0.7 — algebraic threshold-secrecy proof witness.
 *
 * Educational field F_17 ONLY. Exhaustive enumeration, deterministic values,
 * NO cryptographic RNG, usable keys, network code, persistence or real secrets.
 *
 * Proof idea: f_e(X) = s + a_e X + b_e X^2 over F_17, with a_e,b_e sampled
 * independently and uniformly in every epoch. For 1 or 2 distinct nonzero
 * evaluation positions, the linear map from (a_e,b_e) to observed shares has
 * full row rank, so the view is uniform independently of s. Independent
 * epochs multiply these independent uniform likelihoods.
 */
export const PRIME = 17;
export const SHARE_COUNT = 5;
export const THRESHOLD = 3;
const field = value => ((value % PRIME) + PRIME) % PRIME;
const requireField = (value, name) => {
  if (!Number.isInteger(value) || value < 0 || value >= PRIME)
    throw new RangeError('Invalid field value: ' + name);
};
const requireX = x => {
  if (!Number.isInteger(x) || x < 1 || x > SHARE_COUNT)
    throw new RangeError('Invalid share position');
};
function power(base, exp) {
  let a = field(base), result = 1;
  for (let e=exp; e>0; e=Math.floor(e/2)) {
    if(e%2) result=field(result*a);
    a=field(a*a);
  }
  return result;
}
const inverse = x => {
  if (field(x) === 0) throw new RangeError('Non-invertible share position');
  return power(x, PRIME-2);
};

export function evaluate(secret, a, b, x) {
  requireField(secret,'secret'); requireField(a,'a'); requireField(b,'b'); requireX(x);
  return field(secret + a*x + b*x*x);
}
export function shares(secret, a, b) {
  return Array.from({length:SHARE_COUNT},(_,i)=>({x:i+1,y:evaluate(secret,a,b,i+1)}));
}
function validateObservations(observations) {
  if(!Array.isArray(observations) || observations.length>SHARE_COUNT)
    throw new TypeError('Invalid observations');
  const used=new Set();
  for(const row of observations) {
    if(!row || typeof row!=='object' || Array.isArray(row) ||
      Object.keys(row).sort().join(',') !== 'x,y')
      throw new TypeError('Observations require x and y only');
    requireX(row.x); requireField(row.y,'share');
    if(used.has(row.x)) throw new TypeError('Duplicate share position');
    used.add(row.x);
  }
  return observations;
}
export function reconstructThree(input) {
  const points=validateObservations(input);
  if(points.length!==THRESHOLD) throw new RangeError('Require exactly 3 shares of the same epoch');
  let secret=0;
  for(let i=0;i<points.length;i++) {
    let weight=1;
    for(let j=0;j<points.length;j++) {
      if(i===j) continue;
      weight=field(weight * field(-points[j].x) * inverse(points[i].x-points[j].x));
    }
    secret=field(secret + points[i].y*weight);
  }
  return secret;
}
export function compatibleSecretCounts(observations) {
  const rows=validateObservations(observations);
  // Exhaust the 17^2 coefficient assignments for EACH candidate secret.
  const counts=Array(PRIME).fill(0);
  for(let secret=0;secret<PRIME;secret++) {
    for(let a=0;a<PRIME;a++)for(let b=0;b<PRIME;b++) {
      if(rows.every(({x,y})=>evaluate(secret,a,b,x)===y))counts[secret]++;
    }
  }
  return counts;
}
export function independentEpochCounts(epochObservations) {
  if(!Array.isArray(epochObservations) || epochObservations.length<1 || epochObservations.length>20)
    throw new RangeError('Require 1..20 independent epochs');
  const counts=Array(PRIME).fill(1);
  for(const view of epochObservations) {
    const epochCounts=compatibleSecretCounts(view);
    for(let i=0;i<PRIME;i++) counts[i]*=epochCounts[i];
  }
  return counts;
}
export function exhaustiveTwoShareSecurity() {
  let checkedExperiments=0;
  for(let x1=1;x1<=SHARE_COUNT;x1++)for(let x2=x1+1;x2<=SHARE_COUNT;x2++) {
    // For each secret and each pair of outputs, precisely one coefficient
    // assignment exists: observed shares reveal zero information about s.
    for(let secret=0;secret<PRIME;secret++) {
      const histogram=new Uint16Array(PRIME*PRIME);
      for(let a=0;a<PRIME;a++)for(let b=0;b<PRIME;b++) {
        const y1=evaluate(secret,a,b,x1), y2=evaluate(secret,a,b,x2);
        histogram[y1*PRIME+y2]++;
        checkedExperiments++;
      }
      if(histogram.some(n=>n!==1)) throw new Error('Two-share secrecy failed');
    }
  }
  return {checkedExperiments, allTwoShareViewsExactlyUniform:true,
    maxInformationLeakBitsForThisModel:0};
}
export function exhaustiveThreeShareRecovery() {
  let checkedExperiments=0;
  for(let secret=0;secret<PRIME;secret++)for(let a=0;a<PRIME;a++)for(let b=0;b<PRIME;b++) {
    const data=shares(secret,a,b);
    for(let i=0;i<SHARE_COUNT;i++)for(let j=i+1;j<SHARE_COUNT;j++)
      for(let k=j+1;k<SHARE_COUNT;k++) {
        if(reconstructThree([data[i],data[j],data[k]])!==secret)
          throw new Error('Three-share correctness failed');
        checkedExperiments++;
      }
  }
  return {checkedExperiments, allThreeShareReconstructionsExact:true};
}
export function refreshDemo() {
  // Same constant term, different independent nonconstant terms.
  // The client or relays performing secure refresh is NOT implemented here.
  const before=shares(7,3,2), after=shares(7,9,5);
  const oldTwo=[before[0],before[1]];
  const newTwo=[after[2],after[3]];
  const combinations=independentEpochCounts([oldTwo,newTwo]);
  const staticCapture=reconstructThree([before[0],before[1],before[2]]);
  const mixedInvalid=reconstructThree([before[0],before[1],after[2]]);
  const breakAfterThreshold=reconstructThree([after[0],after[1],after[2]]);
  return {
    originalSecret:7,oldShares:oldTwo,newShares:newTwo,
    compatibleCandidateSecrets:combinations.filter(x=>x>0).length,
    allCandidatesSameLikelihood:combinations.every(x=>x===combinations[0]),
    guessedSecretAfterMixedEpochInterpolation:mixedInvalid,
    staticEpochThresholdReconstruction:staticCapture,
    activeEpochThresholdReconstruction:breakAfterThreshold,
    epochsIndependentlyRandomizedAssumption:true,
    physicalCompromiseResilienceProven:false
  };
}
export function runProofWitness() {
  const c=exhaustiveTwoShareSecurity();
  const r=exhaustiveThreeShareRecovery();
  const refresh=refreshDemo();
  return {
    schema:'scattering-v07-f17-educational-exhaustive-witness',
    secrecy:c,reconstruction:r,refresh,
    conditionalTheorem:'Under independently uniform secret-independent coefficients, distinct nonzero positions and fewer than three shares per epoch, all observed views are independent of the secret.',
    fieldBits:Math.log2(PRIME),
    actualProductionCryptography:false,secretSharingProtocolImplemented:false,
    realNetworkMeasured:false,independentAuditCompleted:false,
    wholeSystemSecurity9999999Proven:false,releaseAuthorized:false,
  };
}
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';
if (process.argv[1] && resolve(process.argv[1])===fileURLToPath(import.meta.url)) {
  console.log(JSON.stringify(runProofWitness(),null,2));
}
