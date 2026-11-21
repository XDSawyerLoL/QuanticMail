// Fixed membership BFT sizing; not an estimate of real compromise probability.
const check=v=>{if(!v)throw Error('Invalid Pay committee size');};
export function payCommittee(size){
 check(Number.isInteger(size)&&size>=4&&size<=31&&(size-1)%3===0);
 const faults=(size-1)/3,quorum=2*faults+1;
 return Object.freeze({size,faults,quorum,intersection:2*quorum-size,simulationOnly:true});
}
