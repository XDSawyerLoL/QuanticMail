// Synthetic signing boundary, round zero only. The operator provisions keys,
// exact current roster/anchor and direct local witness clients. No exported
// arbitrary-sign API. Not native Identity Vault or hardware key custody.
// A stale cached grant is not a fresh RPC response: do not deploy this local
// interface across an untrusted network without challenge-bound freshness.
import {createHash} from 'node:crypto';
import {createPayRoundLab} from './pay-round-lab.mjs';
import {openQuorumFenceLab} from './pay-quorum-fence-lab.mjs';
const check=x=>{if(!x)throw Error('Gated Pay signing refused');};
const hash=x=>createHash('sha256').update(JSON.stringify(x)).digest('hex');
const hex=x=>typeof x==='string'&&/^[a-f0-9]{64}$/.test(x);
const ZERO='0'.repeat(64);
export function openQuorumPayRoundLab({fenceConfig,anchor,authorities,validateCandidate}){
 const cfg=structuredClone(fenceConfig),a=structuredClone(anchor),members=structuredClone(authorities);
 check(typeof validateCandidate==='function'&&Array.isArray(members)&&members.length===16&&a&&Object.keys(a).length===5&&Number.isInteger(a.epoch)&&a.epoch>=0&&a.epoch<=65535&&Number.isInteger(a.height)&&a.height>=0&&a.height<256&&hex(a.root)&&hex(a.tip)&&hex(a.committee));
 const committee=hash(['quantic-handoff-roster/lab/v1',members.map(m=>[m.pin,m.pqPin]).sort((x,y)=>x[0]<y[0]?-1:1)]);
 check(a.committee===committee&&(a.epoch===0?a.tip===ZERO&&committee===cfg.initialCommittee:a.tip!==ZERO));
 if(a.height===0)check(a.root===cfg.genesisRoot&&a.epoch===0);
 const domain=a.epoch===0?['quantic-shard-round/v1',cfg.network,cfg.shard]:['quantic-shard-epoch-round/lab/v1',cfg.network,cfg.shard,a.epoch,a.tip];
 const round=createPayRoundLab({network:hash(domain),height:a.height+1,previousRoot:a.root,authorities:members,admissionRound:true,committeeMode:true});
 const fence=openQuorumFenceLab(cfg);
 function request(value){check(hex(value));return {anchor:structuredClone(a),mode:'vote',value};}
 function validate(value,candidate){check(hex(value)&&validateCandidate(structuredClone(candidate))===value);}
 function verifyDecision(r,c){check(JSON.stringify(r)===JSON.stringify(request(r.value)));check(round.finalized(c).value===r.value&&c.prepared.round===0&&c.commit.round===0);return {value:r.value};}
 function openAuthority({credentials,witnessClients}){
  check(Array.isArray(witnessClients)&&witnessClients.length>=3&&witnessClients.length<=4&&witnessClients.every(w=>typeof w.grant==='function'));
  const clients=[...witnessClients],authority=round.openAuthority(credentials);
  let chosen=null,closed=false;
  function permit(value){
   check(!closed);const r=request(value),grants=[];
   for(const w of clients){try{grants.push(w.grant(structuredClone(r)));}catch{}}
   // Invalid/duplicate grants fail closed. Never accept caller-supplied grants.
   fence.verifyGrants(r,grants);return r;
  }
  return Object.freeze({
   prepare({value,candidate}){
    check(!closed&&(chosen===null||chosen===value));validate(value,candidate);
    permit(value);const vote=authority.prepare({round:0,value});chosen=value;return vote;
   },
   commit(qc){
    check(!closed&&chosen!==null&&qc?.round===0&&qc.value===chosen);
    const prepared=round.prepared(qc);permit(chosen);return authority.commit(prepared);
   },
   close(){closed=true;chosen=null;}
  });
 }
 return Object.freeze({scope:round.scope,request,verifyDecision,openAuthority,verifyGrants:fence.verifyGrants});
}
