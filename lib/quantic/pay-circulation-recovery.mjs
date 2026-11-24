// Recover an existing certificate without new signatures, unlocks, or time-based
// rewrites. Four independently pinned witnesses; at most one Byzantine;
// trusted genesis and non-rolled-back honest stores are required.
// A genuine split with no recoverable certificate remains blocked.
import {createCirculationLab} from './pay-circulation-lab.mjs';
const check=v=>{if(!v)throw Error('Circulation recovery refused');};
export function recoverCirculationCertificate({config,records,reports}){
 const lab=createCirculationLab(config),base=lab.snapshot(records);
 check(Array.isArray(reports)&&reports.length<=4);
 const groups=new Map(),seen=new Set();
 for(const report of reports){
  if(report===null)continue;
  try{
   const {proof,decidedAt,vote}=report;
   const info=lab.inspectVote(records,proof,decidedAt,vote);
   check(info.sequence===base.sequence+1);
   if(seen.has(vote.pin))return Object.freeze({state:'duplicate-or-equivocating-report',certificate:null,simulationOnly:true,automaticUnlock:false});
   seen.add(vote.pin);
   const k=JSON.stringify([info.sequence,info.digest,info.root,decidedAt]);
   const g=groups.get(k)??{proof:structuredClone(proof),decidedAt,votes:[]};
   g.votes.push(structuredClone(vote));groups.set(k,g);
  }catch{/* Unverified, stale or malformed reports never count. */}
 }
 const candidates=[...groups.values()].filter(g=>g.votes.length>=3);
 check(candidates.length<=1);
 if(!candidates.length)return Object.freeze({state:'blocked-no-certificate',certificate:null,verifiedVotes:seen.size,groupSizes:Object.freeze([...groups.values()].map(g=>g.votes.length).sort((a,b)=>b-a)),simulationOnly:true,automaticUnlock:false});
 const certificate=candidates[0];
 // Recheck complete certificate including payer authorization and transition.
 const result=lab.snapshot([...records,certificate]);
 return Object.freeze({state:'certificate-recovered',certificate,result,simulationOnly:true,automaticUnlock:false,realPaymentAuthorized:false,settlementVerified:false});
}
