// Lossless V3 view certificate dictionary. Not signature aggregation.
// Structural decoding is NOT cryptographic verification; use selectView.
import {payCommittee} from './pay-committee.mjs';
const check=v=>{if(!v)throw Error('Compact Pay view refused');};
const exact=(o,k)=>o&&typeof o==='object'&&!Array.isArray(o)&&Object.keys(o).length===k.length&&k.every(x=>Object.hasOwn(o,x));
const hex=v=>typeof v==='string'&&/^[a-f0-9]{64}$/.test(v);
const round=v=>Number.isInteger(v)&&v>=0&&v<=1024;
const sig=(v,n)=>typeof v==='string'&&v.length===Math.ceil(n*8/6)&&/^[A-Za-z0-9_-]+$/.test(v);
const index=(i,n)=>Number.isInteger(i)&&i>=0&&i<n;
export const COMPACT_VIEW_FORMAT='quantic-pay-compact-view/v1';
function vote(v){
 check(exact(v,['pin','pqPin','signature','pqSignature'])&&hex(v.pin)&&hex(v.pqPin)&&sig(v.signature,64)&&sig(v.pqSignature,3309));
 return {pin:v.pin,pqPin:v.pqPin,signature:v.signature,pqSignature:v.pqSignature};
}
function shape(c,size){
 const {quorum}=payCommittee(size);
 check(exact(c,['scope','round','reports'])&&hex(c.scope)&&round(c.round)&&c.round>0&&Array.isArray(c.reports)&&c.reports.length>=quorum&&c.reports.length<=size);
 return quorum;
}
export function compactPayView(c,size){
 const quorum=shape(c,size),votes=[],proofs=[],voteIndex=new Map(),proofIndex=new Map();
 function intern(v){
  const clean=vote(v),key=JSON.stringify(clean);
  if(!voteIndex.has(key)){check(votes.length<size*(size+1));voteIndex.set(key,votes.length);votes.push(clean);}
  return voteIndex.get(key);
 }
 const reports=c.reports.map(r=>{
  check(exact(r,['scope','round','prepared','vote'])&&r.scope===c.scope&&r.round===c.round);
  let prepared=null;
  if(r.prepared!==null){
   const p=r.prepared;
   check(exact(p,['scope','round','value','votes'])&&p.scope===c.scope&&round(p.round)&&p.round<c.round&&hex(p.value)&&Array.isArray(p.votes)&&p.votes.length>=quorum&&p.votes.length<=size);
   const refs=p.votes.map(intern);
   check(new Set(refs).size===refs.length);
   const clean={round:p.round,value:p.value,votes:refs},key=JSON.stringify(clean);
   if(!proofIndex.has(key)){proofIndex.set(key,proofs.length);proofs.push(clean);}
   prepared=proofIndex.get(key);
  }
  return {prepared,vote:intern(r.vote)};
 });
 return {format:COMPACT_VIEW_FORMAT,scope:c.scope,round:c.round,votes,proofs,reports};
}
export function expandPayView(c,size){
 const {quorum}=payCommittee(size);
 check(exact(c,['format','scope','round','votes','proofs','reports'])&&c.format===COMPACT_VIEW_FORMAT&&hex(c.scope)&&round(c.round)&&c.round>0);
 check(Array.isArray(c.votes)&&c.votes.length>=quorum&&c.votes.length<=size*(size+1)&&Array.isArray(c.proofs)&&c.proofs.length<=size&&Array.isArray(c.reports)&&c.reports.length>=quorum&&c.reports.length<=size);
 const votes=c.votes.map(vote),usedVotes=new Set(),usedProofs=new Set();
 check(new Set(votes.map(v=>JSON.stringify(v))).size===votes.length);
 function get(i){check(index(i,votes.length));usedVotes.add(i);return votes[i];}
 const proofKeys=new Set();
 const proofs=c.proofs.map(p=>{
  check(exact(p,['round','value','votes'])&&round(p.round)&&p.round<c.round&&hex(p.value)&&Array.isArray(p.votes)&&p.votes.length>=quorum&&p.votes.length<=size&&new Set(p.votes).size===p.votes.length);
  const k=JSON.stringify([p.round,p.value,p.votes]);check(!proofKeys.has(k));proofKeys.add(k);
  return {scope:c.scope,round:p.round,value:p.value,votes:p.votes.map(get)};
 });
 const reports=c.reports.map(r=>{
  check(exact(r,['prepared','vote'])&&(r.prepared===null||index(r.prepared,proofs.length)));
  if(r.prepared!==null)usedProofs.add(r.prepared);
  return {scope:c.scope,round:c.round,prepared:r.prepared===null?null:proofs[r.prepared],vote:get(r.vote)};
 });
 check(usedVotes.size===votes.length&&usedProofs.size===proofs.length);
 return {scope:c.scope,round:c.round,reports};
}
