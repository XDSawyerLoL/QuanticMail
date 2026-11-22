// Synthetic handoff verifier, NOT live committee activation. Honest signers
// must freeze the outgoing ledger at the certified anchor, durably lock one
// successor, and validate the incoming state. Anchor freshness is external.
import {createHash,createPublicKey,verify} from 'node:crypto';
const check=x=>{if(!x)throw Error('Committee handoff refused');};
const raw=x=>Buffer.from(JSON.stringify(x));
const digest=x=>createHash('sha256').update(raw(x)).digest('hex');
const pin=b=>createHash('sha256').update(b).digest('hex');
const hex=x=>typeof x==='string'&&/^[a-f0-9]{64}$/.test(x);
const exact=(o,k)=>o&&typeof o==='object'&&!Array.isArray(o)&&Object.keys(o).length===k.length&&k.every(x=>Object.hasOwn(o,x));
const integer=(x,a,b)=>Number.isSafeInteger(x)&&x>=a&&x<=b;
function bytes(s,n){check(typeof s==='string'&&s.length===Math.ceil(n*8/6)&&/^[A-Za-z0-9_-]+$/.test(s));const b=Buffer.from(s,'base64url');check(b.length===n&&b.toString('base64url')===s);return b;}
function key(s,n,type,p){const b=bytes(s,n),k=createPublicKey({key:b,type:'spki',format:'der'});check(k.asymmetricKeyType===type&&pin(b)===p&&k.export({type:'spki',format:'der'}).equals(b));return k;}
function roster(input){
 check(Array.isArray(input)&&input.length===16);const pins=new Set();
 const members=input.map(m=>{check(exact(m,['pin','pqPin','publicKey','pqPublicKey'])&&hex(m.pin)&&hex(m.pqPin)&&m.pin!==m.pqPin&&!pins.has(m.pin)&&!pins.has(m.pqPin));pins.add(m.pin);pins.add(m.pqPin);
  return {pin:m.pin,pqPin:m.pqPin,publicKey:m.publicKey,pqPublicKey:m.pqPublicKey,cl:key(m.publicKey,44,'ed25519',m.pin),pq:key(m.pqPublicKey,1974,'ml-dsa-65',m.pqPin)};
 }).sort((a,b)=>a.pin<b.pin?-1:1);
 return {id:digest(['quantic-handoff-roster/lab/v1',members.map(m=>[m.pin,m.pqPin])]),members};
}
const publicRoster=r=>r.members.map(({pin,pqPin,publicKey,pqPublicKey})=>({pin,pqPin,publicKey,pqPublicKey}));
const ZERO='0'.repeat(64);
export function openCommitteeHandoffLab({network,shard,initialMembers}){
 check(hex(network)&&typeof shard==='string'&&/^demo-[a-z0-9]{1,24}$/.test(shard));
 let current=roster(initialMembers),epoch=0,height=0,tip=ZERO;
 function validate(p,anchor){
  check(exact(anchor,['network','shard','height','root'])&&anchor.network===network&&anchor.shard===shard&&integer(anchor.height,height+1,Number.MAX_SAFE_INTEGER-1)&&hex(anchor.root));
  check(exact(p,['network','shard','epoch','previous','outgoing','incoming','height','root','nextMembers'])&&p.network===network&&p.shard===shard&&p.epoch===epoch+1&&p.epoch<=65535&&p.previous===tip&&p.outgoing===current.id&&p.height===anchor.height&&p.root===anchor.root);
  const next=roster(p.nextMembers);check(next.id===p.incoming&&next.id!==current.id&&JSON.stringify(publicRoster(next))===JSON.stringify(p.nextMembers));
  // Any reused key must retain its original classical/PQ pairing.
  for(const a of current.members)for(const b of next.members)if(a.pin===b.pin||a.pqPin===b.pqPin)check(a.pin===b.pin&&a.pqPin===b.pqPin);
  return {next,id:digest(['quantic-handoff/lab/v1',network,shard,p.epoch,p.previous,p.outgoing,p.incoming,p.height,p.root])};
 }
 function message(phase,id,oldHash=null){return raw(['quantic-handoff-vote/lab/v1',phase,id,oldHash]);}
 function votes(input,r,msg){
  check(Array.isArray(input)&&input.length>=11&&input.length<=16);
  const sorted=[];let last='';
  for(const v of input){check(exact(v,['pin','pqPin','signature','pqSignature'])&&hex(v.pin)&&v.pin>last);last=v.pin;
   const m=r.members.find(m=>m.pin===v.pin);check(m&&m.pqPin===v.pqPin&&verify(null,msg,m.cl,bytes(v.signature,64))&&verify(null,msg,m.pq,bytes(v.pqSignature,3309)));
   sorted.push([v.pin,v.pqPin,v.signature,v.pqSignature]);
  }
  return digest(['quantic-handoff-votes/lab/v1',sorted]);
 }
 return Object.freeze({
  current:()=>({network,shard,epoch,height,tip,committee:current.id,members:publicRoster(current),simulationOnly:true}),
  draft(anchor,nextMembers){const next=roster(nextMembers),p={network,shard,epoch:epoch+1,previous:tip,outgoing:current.id,incoming:next.id,height:anchor.height,root:anchor.root,nextMembers:publicRoster(next)};validate(p,anchor);return p;},
  outgoingBytes(p,anchor){return message('outgoing',validate(p,anchor).id);},
  incomingBytes(p,anchor,outgoing){const {id}=validate(p,anchor),oldHash=votes(outgoing,current,message('outgoing',id));return message('incoming',id,oldHash);},
  apply(record,anchor){
   check(exact(record,['proposal','outgoing','incoming']));const {proposal:p,outgoing,incoming}=record,{next,id}=validate(p,anchor);
   const oldHash=votes(outgoing,current,message('outgoing',id));votes(incoming,next,message('incoming',id,oldHash));
   // The transition identifier commits to semantics, not the particular
   // valid subset or randomized signatures on the same decision.
   current=next;epoch=p.epoch;height=p.height;tip=id;
   return {epoch,height,tip,committee:current.id,activationHeight:height+1,simulationOnly:true,realPaymentAuthorized:false};
  }
 });
}
