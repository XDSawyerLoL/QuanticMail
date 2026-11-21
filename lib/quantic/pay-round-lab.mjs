// Experimental PBFT-style single-height round-change laboratory. Separate
// domain, synthetic proposals only. Not a production BFT implementation.
// Requires <=1 Byzantine authority, trusted fixed membership, authenticated
// communication and non-rolled-back honest state. No asynchronous liveness claim.
import {createHash,createPublicKey,sign,verify} from 'node:crypto';
const check=v=>{if(!v)throw Error('Pay round laboratory refused');};
const sha=b=>createHash('sha256').update(b).digest('hex');
const encode=v=>Buffer.from(JSON.stringify(v));
const hex=/^[a-f0-9]{64}$/;
const spki=k=>k.export({format:'der',type:'spki'});
const pin=k=>sha(spki(k));
function decode(s,n){
 check(typeof s==='string'&&s.length===Math.ceil(n*8/6)&&/^[A-Za-z0-9_-]+$/.test(s));
 const b=Buffer.from(s,'base64url');check(b.length===n&&b.toString('base64url')===s);return b;
}
function pub(s,p,t,n){const b=decode(s,n),k=createPublicKey({key:b,format:'der',type:'spki'});check(k.asymmetricKeyType===t&&pin(k)===p&&spki(k).equals(b));return k;}
const round=r=>Number.isSafeInteger(r)&&r>=0&&r<=1024;
const value=v=>v==='demo-alpha'||v==='demo-beta';
export function createPayRoundLab({network,height,previousRoot,authorities}){
 check(typeof network==='string'&&hex.test(network)&&typeof previousRoot==='string'&&hex.test(previousRoot)&&Number.isSafeInteger(height)&&height>=1&&height<=256&&Array.isArray(authorities)&&authorities.length===4);
 const keys=new Map(),pins=new Set();
 for(const a of structuredClone(authorities)){
  check(!pins.has(a.pin)&&!pins.has(a.pqPin)&&a.pin!==a.pqPin);
  const cl=pub(a.publicKey,a.pin,'ed25519',44),pq=pub(a.pqPublicKey,a.pqPin,'ml-dsa-65',1974);
  pins.add(a.pin);pins.add(a.pqPin);keys.set(a.pin,{pin:a.pin,pqPin:a.pqPin,cl,pq});
 }
 const members=[...keys.values()].sort((a,b)=>a.pin<b.pin?-1:1);
 const scope=sha(encode(['quantic-pay-round-lab/v1',network,height,previousRoot,members.map(a=>[a.pin,a.pqPin]),true]));
 function bytes(phase,r,v,a){return encode(['quantic-pay-round-vote/v1',scope,phase,r,v,a.pin,a.pqPin]);}
 function signed(phase,r,v,a,cl,pq){
  const b=bytes(phase,r,v,a);
  return Object.freeze({pin:a.pin,pqPin:a.pqPin,signature:sign(null,b,cl).toString('base64url'),pqSignature:sign(null,b,pq).toString('base64url')});
 }
 function verifyVote(phase,r,v,s){
  const a=keys.get(s?.pin);check(a&&s.pqPin===a.pqPin);
  const b=bytes(phase,r,v,a);
  check(verify(null,b,a.cl,decode(s.signature,64))&&verify(null,b,a.pq,decode(s.pqSignature,3309)));return a.pin;
 }
 function certificate(phase,c){
  check(c&&c.scope===scope&&round(c.round)&&value(c.value)&&Array.isArray(c.votes)&&c.votes.length>=3&&c.votes.length<=4);
  const seen=new Set();for(const s of c.votes){const p=verifyVote(phase,c.round,c.value,s);check(!seen.has(p));seen.add(p);}
  return Object.freeze({scope,round:c.round,value:c.value,votes:structuredClone(c.votes)});
 }
 function prepared(c){return certificate('prepare',c);}
 function finalized(c){const qc=prepared(c?.prepared);const commit=certificate('commit',c?.commit);check(qc.round===commit.round&&qc.value===commit.value);return Object.freeze({scope,round:qc.round,value:qc.value,simulationOnly:true,realPaymentAuthorized:false});}
 function claim(report,target){
  check(report?.scope===scope&&report.round===target&&round(target)&&target>0);
  const qc=report.prepared===null?null:prepared(report.prepared);
  check(qc===null||qc.round<target);
  // Bind the exact certified value and round, not arbitrary JSON/reordered votes.
  const v=qc===null?null:[qc.round,qc.value];
  const p=verifyVote('view-change',target,v,report.vote);
  return {p,qc};
 }
 function selectView(c){
  check(c?.scope===scope&&round(c.round)&&c.round>0&&Array.isArray(c.reports)&&c.reports.length>=3&&c.reports.length<=4);
  const seen=new Set();let highest=null;
  for(const report of c.reports){
   const {p,qc}=claim(report,c.round);check(!seen.has(p));seen.add(p);
   if(qc){if(!highest||qc.round>highest.round)highest=qc;else if(qc.round===highest.round)check(qc.value===highest.value);}
  }
  return Object.freeze({round:c.round,requiredValue:highest?.value??null,preparedRound:highest?.round??null});
 }
 function openAuthority({authorityPin,classicalPrivateKey,pqPrivateKey}){
  const a=keys.get(authorityPin);
  check(a&&classicalPrivateKey?.type==='private'&&pqPrivateKey?.type==='private'&&pin(createPublicKey(classicalPrivateKey))===a.pin&&pin(createPublicKey(pqPrivateKey))===a.pqPin);
  let current=0,highest=null,prepareVote=null,commitVote=null,viewReport=null,viewChoice=null,done=null;
  const signVote=(phase,r,v)=>signed(phase,r,v,a,classicalPrivateKey,pqPrivateKey);
  function ensureOpen(){check(done===null);}
  return Object.freeze({
   status:()=>Object.freeze({currentRound:current,preparedRound:highest?.round??null,preparedValue:highest?.value??null,finalValue:done?.value??null,ephemeral:true}),
   changeView(target){
    ensureOpen();check(round(target)&&target>=current&&target>0);
    if(target===current){check(viewReport);return structuredClone(viewReport);}
    current=target;prepareVote=null;commitVote=null;viewChoice=null;
    const qc=highest?structuredClone(highest):null;
    viewReport={scope,round:target,prepared:qc,vote:signVote('view-change',target,qc?[qc.round,qc.value]:null)};
    return structuredClone(viewReport);
   },
   prepare({round:r,value:v,viewCertificate=null}){
    ensureOpen();check(round(r)&&r===current&&value(v));
    let required=null;
    if(r===0)check(viewCertificate===null);
    else{
     const choice=selectView(viewCertificate);check(choice.round===r);required=choice.requiredValue;
     check(required===null||required===v);
     if(viewChoice!==null)check(viewChoice===v);
     viewChoice=v;
    }
    if(prepareVote){check(prepareVote.value===v);return structuredClone(prepareVote.vote);}
    prepareVote={value:v,vote:signVote('prepare',r,v)};return structuredClone(prepareVote.vote);
   },
   commit(qc){
    ensureOpen();const c=prepared(qc);check(c.round===current&&prepareVote?.value===c.value);
    if(commitVote){check(commitVote.value===c.value);return structuredClone(commitVote.vote);}
    // Before releasing a commit vote, retain the prepared certificate for
    // subsequent view-change reports. Durable custody is a separate requirement.
    highest=structuredClone(c);
    commitVote={value:c.value,vote:signVote('commit',current,c.value)};return structuredClone(commitVote.vote);
   },
   learn(c){
    const f=finalized(c);
    if(done)check(done.value===f.value);else done=f;
    return done;
   }
  });
 }
 // Public validation of retained individual signed outputs. A matching
 // semantic result is not equivalent to a quorum or a new authorization.
 function inspectOutput(action,input,out,authorityPin){
  if(action==='changeView'){
   const {p,qc}=claim(out,input);check(p===authorityPin);
   return [action,input,qc?.round??null,qc?.value??null];
  }
  if(action==='prepare'||action==='commit'){
   check(round(input.round)&&value(input.value)&&verifyVote(action,input.round,input.value,out)===authorityPin);
   return [action,input.round,input.value];
  }
  if(action==='learn'){
   const expected=finalized(input);check(JSON.stringify(out)===JSON.stringify(expected));return [action,expected.round,expected.value];
  }
  throw Error('Unknown round action');
 }
 return Object.freeze({scope,prepared,finalized,selectView,openAuthority,inspectOutput});
}
