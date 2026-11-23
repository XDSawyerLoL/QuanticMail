/** Deterministic, seedable synthetic benchmark. No physical network claims. */
import {createHash} from 'node:crypto';
import {dataPositions, scheduleKey} from './scheduler.mjs';
import {stratifiedSlots} from './transport.mjs';

function digest(s){return createHash('sha256').update(String(s)).digest();}
function int(seed,n){return digest(seed).readUInt32BE(0)%n;}
function maskFor(attack,trial,{slots=28,baseline=[]}={}){
 const set=new Set();
 if(attack==='public_target9')return new Set(baseline.slice(0,9));
 if(attack==='antipodal_pairs14')return new Set([0,1,2,3,4,5,6,14,15,16,17,18,19,20]);
 if(attack==='antipodal_paired9')return new Set([0,1,2,3,4,14,15,16,17]);
 if(attack==='first14')return new Set(Array.from({length:14},(_,i)=>i));
 if(attack==='last14')return new Set(Array.from({length:14},(_,i)=>slots-14+i));
 if(attack==='burst14'){
  const start=int(`burst:${trial}`,slots-13);
  return new Set(Array.from({length:14},(_,i)=>start+i));
 }
 if(attack==='split7plus7'){
  const start=int(`split-a:${trial}`,slots-6);
  const second=(start+7+int(`split-b:${trial}`,slots-13))%slots;
  return new Set([...Array.from({length:7},(_,i)=>(start+i)%slots),...Array.from({length:7},(_,i)=>(second+i)%slots)]);
 }
 if(attack==='random14'){
  const all=Array.from({length:slots},(_,i)=>i);
  for(let i=all.length-1;i>0;i--){const j=int(`mask:${trial}:${i}`,i+1);[all[i],all[j]]=[all[j],all[i]];}
  return new Set(all.slice(0,14));
 }
 if(attack==='iid2'){
  for(let i=0;i<slots;i++)if(int(`iid:${trial}:${i}`,10000)<200)set.add(i);
  return set;
 }
 throw new Error('Unknown attack');
}
const MODES=['public_stratified','keyed_stratified','keyed_uniform','keyed_antipodal'];
const ATTACKS=['iid2','burst14','split7plus7','first14','last14','random14','public_target9','antipodal_paired9','antipodal_pairs14'];
export function runBenchmark({trials=1000,seed='quantic-v14-public-test-seed',slots=28}={}){
 if(!Number.isInteger(trials)||trials<1||trials>250000)throw new RangeError('Invalid trial count');
 const baseline=stratifiedSlots(slots,16),master=digest(`master:${seed}`),sessionId=digest(`session:${seed}`).subarray(0,16),key=scheduleKey(master,sessionId);
 const result={version:'v14',type:'SYNTHETIC_MODEL_NOT_LAN',seed,trials,slots,framesBytes:168,activeShards:16,minShards:8,attacks:{},notes:['Same 28 frames for cover or useful data','Loss masks paired across methods per trial','No claim of physical signal invisibility','Tested attacks only, not arbitrary active adversary']};
 for(const attack of ATTACKS){
  const wins=Object.fromEntries(MODES.map(x=>[x,0]));
  for(let t=0;t<trials;t++){
   const dropped=maskFor(attack,`${seed}:${t}`,{slots,baseline});
   for(const mode of MODES){
    const positions=dataPositions(key,t,{slots,shards:16,mode});
    const survived=positions.filter(x=>!dropped.has(x)).length;
    if(survived>=8)wins[mode]++;
   }
  }
  result.attacks[attack]=Object.fromEntries(MODES.map(m=>[m,{recovered:wins[m],rate:wins[m]/trials}]));
 }
 return result;
}
