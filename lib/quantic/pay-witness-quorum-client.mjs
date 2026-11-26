// Four explicitly configured, separate local Scattering carrier endpoints.
// The wallet must still verify the signed 3/4 checkpoint; HTTP success is not a vote.
import {createPayScatteringClient} from './pay-scattering-client.mjs';
const check=v=>{if(!v)throw Error('Pay witness quorum transport refused');};
export function createPayWitnessQuorumClient(configs){
 check(Array.isArray(configs)&&configs.length===4&&new Set(configs.map(c=>c.loopbackPort)).size===4&&new Set(configs.map(c=>c.token)).size===4);
 const clients=configs.map(c=>createPayScatteringClient(c));
 return Object.freeze({
  async readVotes(request){
   const results=await Promise.allSettled(clients.map(c=>c.readVotes(request)));
   const votes=results.filter(r=>r.status==='fulfilled'&&r.value.length===1).flatMap(r=>r.value);
   check(votes.length>=3);return votes;
  },
  async submitProof(proof,prior){
   const results=await Promise.allSettled(clients.map(c=>c.submitProof(proof,prior)));
   check(results.filter(r=>r.status==='fulfilled').length>=3);
   // Caller must obtain fresh signed post-quorum over the exact expected history.
  }
 });
}
