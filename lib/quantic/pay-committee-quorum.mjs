// Explicit fixed-committee vote collector. The coordinator has no signing keys.
// Never manufacture a missing vote or retry an ambiguous operation.
const check=v=>{if(!v)throw Error('Committee quorum refused');};
export async function collectCommitteeVotes({lab,authorities,phase,round,value,invoke}){
 const {size,quorum}=lab.committee;
 check(Array.isArray(authorities)&&authorities.length>=quorum&&authorities.length<=size&&['prepare','commit'].includes(phase)&&typeof invoke==='function');
 const pins=new Set();
 for(const a of authorities){
  check(typeof a.authorityPin==='string'&&/^[a-f0-9]{64}$/.test(a.authorityPin)&&!pins.has(a.authorityPin));pins.add(a.authorityPin);
 }
 const settled=await Promise.allSettled(authorities.map(async a=>{
  const vote=await invoke(a.client);
  lab.inspectOutput(phase,{round,value},vote,a.authorityPin);
  return vote;
 }));
 const votes=settled.filter(r=>r.status==='fulfilled').map(r=>r.value);
 if(votes.length<quorum)throw Error('Committee quorum refused: '+votes.length+'/'+quorum+' verified votes');
 const certificate={scope:lab.scope,round,value,votes:votes.slice(0,quorum)};
 if(phase==='prepare')lab.prepared(certificate);
 return Object.freeze(certificate);
}
