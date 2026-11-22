// Synthetic 3-of-4 independent anti-rollback witnesses. Fixed membership,
// at most one faulty/rolled-back witness, authenticated callers. A conflicting
// partial lock can halt progress; no view change, RPC, or private-key custody.
import {createHash,createPublicKey,sign,verify} from 'node:crypto';
import {openExternalVoteFence} from './pay-external-vote-fence-lab.mjs';
const check=x=>{if(!x)throw Error('Quorum fence refused');};
const raw=x=>Buffer.from(JSON.stringify(x));
const hash=x=>createHash('sha256').update(raw(x)).digest('hex');
const pin=k=>createHash('sha256').update(k.export({type:'spki',format:'der'})).digest('hex');
const hex=x=>typeof x==='string'&&/^[a-f0-9]{64}$/.test(x);
const exact=(o,k)=>o&&typeof o==='object'&&!Array.isArray(o)&&Object.keys(o).length===k.length&&k.every(x=>Object.hasOwn(o,x));
const int=(x,a,b)=>Number.isSafeInteger(x)&&x>=a&&x<=b;
const bytes=(s,n)=>{check(typeof s==='string'&&s.length===Math.ceil(n*8/6)&&/^[A-Za-z0-9_-]+$/.test(s));const b=Buffer.from(s,'base64url');check(b.length===n&&b.toString('base64url')===s);return b;};
function publicKey(s,n,type,p){const b=bytes(s,n),k=createPublicKey({key:b,type:'spki',format:'der'});check(k.asymmetricKeyType===type&&pin(k)===p&&k.export({type:'spki',format:'der'}).equals(b));return k;}
export function openQuorumFenceLab({network,shard,initialCommittee,genesisRoot,witnesses}){
 check(hex(network)&&typeof shard==='string'&&/^demo-[a-z0-9]{1,24}$/.test(shard)&&hex(initialCommittee)&&hex(genesisRoot)&&Array.isArray(witnesses)&&witnesses.length===4);
 const pins=new Set(),members=new Map();
 for(const w of witnesses){check(exact(w,['pin','pqPin','publicKey','pqPublicKey'])&&hex(w.pin)&&hex(w.pqPin)&&w.pin!==w.pqPin&&!pins.has(w.pin)&&!pins.has(w.pqPin));pins.add(w.pin);pins.add(w.pqPin);members.set(w.pin,{pin:w.pin,pqPin:w.pqPin,cl:publicKey(w.publicKey,44,'ed25519',w.pin),pq:publicKey(w.pqPublicKey,1974,'ml-dsa-65',w.pqPin)});}
 const scope=hash(['quantic-quorum-fence/lab/v1',network,shard,initialCommittee,genesisRoot,[...members.values()].map(w=>[w.pin,w.pqPin]).sort()]);
 function requestBytes(r){
  check(exact(r,['anchor','mode','value'])&&['vote','handoff'].includes(r.mode)&&hex(r.value));const a=r.anchor;
  check(exact(a,['epoch','height','root','committee','tip'])&&int(a.epoch,0,65535)&&int(a.height,0,255)&&hex(a.root)&&hex(a.committee)&&hex(a.tip)&&(r.mode!=='handoff'||a.height>0&&a.epoch<65535));
  return raw(['quantic-fence-grant/lab/v1',scope,a.epoch,a.height,a.root,a.committee,a.tip,r.mode,r.value]);
 }
 function verifyGrants(r,grants){
  const msg=requestBytes(r);check(Array.isArray(grants)&&grants.length>=3&&grants.length<=4);const seen=new Set();
  for(const g of grants){check(exact(g,['pin','pqPin','signature','pqSignature'])&&!seen.has(g.pin));const w=members.get(g.pin);check(w&&w.pqPin===g.pqPin&&verify(null,msg,w.cl,bytes(g.signature,64))&&verify(null,msg,w.pq,bytes(g.pqSignature,3309)));seen.add(g.pin);}
  return Object.freeze({scope,request:hash([...msg]),votes:seen.size,simulationOnly:true});
 }
 function openWitness({directory,credentials,createNew=false,verifyDecision}){
  // Configured locally by the trusted witness operator, NEVER passed by a
  // network requester. The callback must verify real finalized ledger/handoff
  // certificates, including their scope. Mere positive grants are not finality.
  check(typeof verifyDecision==='function');const w=members.get(credentials?.pin),cl=credentials?.classicalPrivateKey,pq=credentials?.pqPrivateKey;
  check(w&&cl?.type==='private'&&pq?.type==='private'&&pin(createPublicKey(cl))===w.pin&&pin(createPublicKey(pq))===w.pqPin);
  const f=openExternalVoteFence({directory,network:hash(['quantic-witness-storage/lab/v1',scope,w.pin]),shard,initialCommittee,genesisRoot,createNew});
  function lock(r){return r.mode==='vote'?f.lockVote(r.anchor,r.value):f.lockHandoff(r.anchor,r.value);}
  return Object.freeze({
   status:f.status,
   grant(input){const r=structuredClone(input),msg=requestBytes(r);lock(r);return {pin:w.pin,pqPin:w.pqPin,signature:sign(null,msg,cl).toString('base64url'),pqSignature:sign(null,msg,pq).toString('base64url')};},
   complete(input,grants,proof){
    const r=structuredClone(input);verifyGrants(r,grants);
    // The local verifier returns the exact committed decision identity. No
    // arbitrary Boolean or caller-supplied next committee is accepted here.
    const v=verifyDecision(structuredClone(r),structuredClone(proof));
    if(r.mode==='vote'){check(exact(v,['value'])&&v.value===r.value);lock(r);return f.advanceBlock(r.anchor,r.value);}
    check(exact(v,['transition','nextCommittee'])&&v.transition===r.value&&hex(v.nextCommittee)&&v.nextCommittee!==r.anchor.committee);
    lock(r);return f.activate(r.anchor,v);
   },close:f.close
  });
 }
 return Object.freeze({scope,verifyGrants,openWitness});
}
