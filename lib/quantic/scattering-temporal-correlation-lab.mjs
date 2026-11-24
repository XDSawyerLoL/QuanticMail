// Passive time-only classifier, evaluated against E2E truth labels OFFLINE.
// Cryptographic keys provide scorer ground truth only, NOT attacker features.
// All inputs are synthetic PCAPs from four isolated namespaces on one host.
import {parseLabPcap} from './scattering-multihop-observer.mjs';
import {openReliable} from '../../labs/quantic-native/scattering/scattering-reliable-lab.mjs';
import {openEndToEndLab,E2E_LAB} from './scattering-e2e-envelope-lab.mjs';

const check=(ok,msg)=>{if(!ok)throw Error(msg)};
const p=(n,d)=>d?+(n/d).toFixed(6):null;
function latestBefore(times,time){
 let low=0,high=times.length;
 while(low<high){const mid=(low+high)>>1;if(times[mid]<=time)low=mid+1;else high=mid;}
 return low?times[low-1]:null;
}
// Returns an attribution from ONLY observed times, independent of keys or labels.
export function timeOnlyNearestIngress({sourceATimes,sourceBTimes,egressTime,maxLagMs=250}){
 check(Array.isArray(sourceATimes)&&Array.isArray(sourceBTimes)&&
  Number.isFinite(egressTime)&&Number.isFinite(maxLagMs)&&maxLagMs>=1&&maxLagMs<=1000&&
  [...sourceATimes,...sourceBTimes].every(Number.isFinite),'invalid timestamps');
 const a=latestBefore(sourceATimes,egressTime),b=latestBefore(sourceBTimes,egressTime);
 const ageA=a===null?Infinity:egressTime-a,ageB=b===null?Infinity:egressTime-b;
 if(Math.min(ageA,ageB)>maxLagMs)return null;
 return ageA<=ageB?'A':'B'; // ties default to A, declared a priori
}
export function evaluateTimeOnlyLab({captureA,captureB,captureEgress,outputHopKey,endToEndKey,maxLagMs=250}){
 check(Buffer.isBuffer(outputHopKey)&&outputHopKey.length===32&&
  Buffer.isBuffer(endToEndKey)&&endToEndKey.length===32&&
  !outputHopKey.equals(endToEndKey),'distinct oracle keys required');
 const a=parseLabPcap(captureA),b=parseLabPcap(captureB),
       output=parseLabPcap(captureEgress,{includeCiphertext:true});
 const timesA=a.packets.map(x=>x.timestampMs),timesB=b.packets.map(x=>x.timestampMs);
 // Observer makes one time-only prediction for EVERY egress packet,
 // including cover cells. It does not know which are the actual messages.
 let correct=0,incorrect=0,unknown=0,labeledData=0,cover=0,guessedCover=0;
 const seen=new Set(),truth={A:0,B:0};
 for(const event of output.packets){
  const guess=timeOnlyNearestIngress({sourceATimes:timesA,sourceBTimes:timesB,
    egressTime:event.timestampMs,maxLagMs});
  const hop=openReliable(outputHopKey,event.ciphertext);
  let inner=null;
  if(hop&&hop.seq!==null&&hop.data.length===E2E_LAB.innerLength)
   inner=openEndToEndLab(endToEndKey,hop.data);
  hop?.data?.fill(0);
  event.ciphertext.fill(0);
  if(!inner){cover++;if(guess)guessedCover++;continue;}
  const key=inner.senderId+':'+inner.seq;
  check(!seen.has(key),'duplicate authenticated E2E data in observation');
  seen.add(key);
  const truthSender=inner.senderId===0?'A':'B';truth[truthSender]++;
  labeledData++;
  if(guess===null)unknown++;
  else if(guess===truthSender)correct++;
  else incorrect++;
  inner.data.fill(0);
 }
 check(labeledData>0&&truth.A>0&&truth.B>0,'insufficient two-source E2E truth');
 return {
  experiment:'fixed-rate two-user timing-only attribution under nested E2E',
  physicalHosts:1,observedPackets:output.packets.length,
  observerFeatures:['ingress A timestamps','ingress B timestamps','egress timestamps'],
  attackerKeysProvided:false,oracleKeysUsedForScoringOnly:true,
  classifier:'last earlier ingress across both links in 250ms lookback, ties A',
  lookbackMs:maxLagMs,
  truth:{A:truth.A,B:truth.B},
  data:{total:labeledData,correct,incorrect,noGuess:unknown,
    accuracyOnGuessed:p(correct,correct+incorrect),
    accuracyOverAllData:p(correct,labeledData),
    majoritySourceBaseline:p(Math.max(truth.A,truth.B),labeledData)},
  cover:{total:cover,guessedSource:guessedCover,
    falseAttributionFraction:p(guessedCover,cover)},
  limitations:'One deterministic timestamp heuristic and one short lab trial; no multi-seed confidence interval, no anonymity proof, no real WAN, no traffic attack beyond source attribution.'
 };
}
