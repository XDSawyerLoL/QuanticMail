// Separate, offline synthetic circulation model. Not the native Pay v1
// transcript, a live account registry, PSP or a distributed consensus service.
import {createHash,createPublicKey,verify,sign} from 'node:crypto';
import {createPayRoundLab} from './pay-round-lab.mjs';
const check=v=>{if(!v)throw Error('Pay circulation laboratory refused');};
const sha=b=>createHash('sha256').update(b).digest('hex');
const hex=/^[a-f0-9]{64}$/;
const id=/^demo-[a-z]{1,24}$/;
const exact=(v,keys)=>v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).length===keys.length&&keys.every(k=>Object.hasOwn(v,k));
function decode(s,n){
 check(typeof s==='string'&&s.length===Math.ceil(n*8/6)&&/^[A-Za-z0-9_-]+$/.test(s));
 const b=Buffer.from(s,'base64url');check(b.length===n&&b.toString('base64url')===s);return b;
}
function key(s,pin,type,len){
 check(typeof pin==='string'&&hex.test(pin));
 const b=decode(s,len),k=createPublicKey({key:b,type:'spki',format:'der'});
 check(sha(b)===pin&&k.asymmetricKeyType===type&&k.export({format:'der',type:'spki'}).equals(b));
 if(type==='ec')check(k.asymmetricKeyDetails.namedCurve==='prime256v1');
 return k;
}
const encode=v=>Buffer.from(JSON.stringify(v));
export function createCirculationLab(config){return createLedger(config,false);}
export function createRoundCirculationLab(config){return createLedger(config,true);}
function createLedger({wallets,witnesses,admissionPolicy=null},multiRound){
 const gated=admissionPolicy==='quorum-v1';
 check(admissionPolicy===null||(multiRound&&gated));
 check(Array.isArray(wallets)&&wallets.length>=2&&wallets.length<=16&&Array.isArray(witnesses)&&witnesses.length===4);
 const accounts=new Map(),authorities=new Map(),used=new Set();
 function unique(p){check(!used.has(p));used.add(p);}
 for(const w of structuredClone(wallets)){
  check(typeof w.id==='string'&&id.test(w.id)&&!accounts.has(w.id)&&Number.isSafeInteger(w.initialCents)&&w.initialCents>=0&&w.initialCents<=10000);
  const classical=key(w.publicKey,w.pin,'ec',91),pq=key(w.pqPublicKey,w.pqPin,'ml-dsa-65',1974);
  unique(w.pin);unique(w.pqPin);accounts.set(w.id,{...w,classical,pq});
 }
 for(const w of structuredClone(witnesses)){
  const classical=key(w.publicKey,w.pin,'ed25519',44),pq=key(w.pqPublicKey,w.pqPin,'ml-dsa-65',1974);
  unique(w.pin);unique(w.pqPin);authorities.set(w.pin,{...w,classical,pq});
 }
 const sorted=[...accounts.values()].sort((a,b)=>a.id<b.id?-1:1);
 const genesis=sha(encode([gated?'quantic-round-chain-gated-genesis/v1':multiRound?'quantic-round-chain-genesis/v1':'quantic-circulation-genesis/v1',sorted.map(w=>[w.id,w.pin,w.pqPin,w.initialCents]),[...authorities.values()].sort((a,b)=>a.pin<b.pin?-1:1).map(w=>[w.pin,w.pqPin]),'EUR',false]));
 const total=sorted.reduce((n,w)=>n+w.initialCents,0);check(total>0);
 function empty(){return {sequence:0,root:genesis,balances:Object.fromEntries(sorted.map(w=>[w.id,w.initialCents])),nonces:new Set()};}
 function transcript(intent){
  check(exact(intent,['network','sequence','previousRoot','payer','payee','payerPin','payerPQPin','payeePin','payeePQPin','cents','currency','nonce','issued','expires','simulationOnly']));
  const a=accounts.get(intent.payer),b=accounts.get(intent.payee);
  check(a&&b&&a!==b&&intent.network===genesis&&Number.isSafeInteger(intent.sequence)&&intent.sequence>=1&&intent.sequence<=256&&typeof intent.previousRoot==='string'&&hex.test(intent.previousRoot));
  check(intent.payerPin===a.pin&&intent.payerPQPin===a.pqPin&&intent.payeePin===b.pin&&intent.payeePQPin===b.pqPin);
  check(Number.isSafeInteger(intent.cents)&&intent.cents>=1&&intent.cents<=total&&intent.currency==='EUR'&&typeof intent.nonce==='string'&&hex.test(intent.nonce)&&Number.isSafeInteger(intent.issued)&&intent.issued>=0&&Number.isSafeInteger(intent.expires)&&intent.expires-intent.issued===120000&&intent.simulationOnly===true);
  return encode([multiRound?'quantic-round-chain-transfer/v1':'quantic-circulation-transfer/v1',genesis,intent.sequence,intent.previousRoot,intent.payer,intent.payee,a.pin,a.pqPin,b.pin,b.pqPin,intent.cents,'EUR',intent.nonce,intent.issued,intent.expires,true]);
 }
 function verifyProof(proof){
  check(exact(proof,['intent','signature','pqSignature']));
  const raw=transcript(proof.intent),a=accounts.get(proof.intent.payer);
  check(verify('sha256',raw,{key:a.classical,dsaEncoding:'ieee-p1363'},decode(proof.signature,64))&&verify(null,raw,a.pq,decode(proof.pqSignature,3309)));
  return sha(raw);
 }
 function advance(s,proof){
  const i=proof.intent,digest=verifyProof(proof);
  check(i.sequence===s.sequence+1&&i.previousRoot===s.root&&!s.nonces.has(i.nonce)&&s.balances[i.payer]>=i.cents);
  const balances={...s.balances};
  balances[i.payer]-=i.cents;balances[i.payee]+=i.cents;
  check(Object.values(balances).every(v=>Number.isSafeInteger(v)&&v>=0)&&Object.values(balances).reduce((a,b)=>a+b,0)===total);
  return {sequence:i.sequence,root:sha(encode([multiRound?'quantic-round-chain-step/v1':'quantic-circulation-step/v1',s.root,digest,sorted.map(w=>[w.id,balances[w.id]])])),balances,nonces:new Set([...s.nonces,i.nonce])};
 }
 function voteBytes(proof,s,decidedAt,a){
  return encode(['quantic-circulation-witness/v1',genesis,a.pin,a.pqPin,proof.intent.sequence,proof.intent.previousRoot,verifyProof(proof),s.root,decidedAt,true]);
 }
 function apply(s,record){
  check(exact(record,['proof','decidedAt','votes']));
  const {proof,decidedAt,votes}=record;
  const next=advance(s,proof);
  check(Number.isSafeInteger(decidedAt)&&decidedAt>=proof.intent.issued&&decidedAt<proof.intent.expires&&Array.isArray(votes)&&votes.length<=4);
  const seen=new Set();
  for(const v of votes){
   try{
    const a=authorities.get(v.pin);check(a&&v.pqPin===a.pqPin&&!seen.has(v.pin));
    const msg=voteBytes(proof,next,decidedAt,a);
    check(verify(null,msg,a.classical,decode(v.signature,64))&&verify(null,msg,a.pq,decode(v.pqSignature,3309)));seen.add(v.pin);
   }catch{/* Invalid votes never count. */}
  }
  check(seen.size>=3);return next;
 }
 function draftAdmission(s,admission){
  check(multiRound&&exact(admission,['proposals','admissionTime'])&&s.sequence<32);
  const {proposals,admissionTime}=admission;
  check(Array.isArray(proposals)&&proposals.length>=1&&proposals.length<=4&&Number.isSafeInteger(admissionTime)&&admissionTime>=0);
  const candidates=new Map();
  for(const proof of proposals){
   const next=advance(s,proof),i=proof.intent;
   check(i.issued<=admissionTime&&admissionTime<i.expires);
   const v=sha(encode(['quantic-round-chain-candidate/v1',genesis,s.root,next.sequence,verifyProof(proof),next.root,admissionTime]));
   check(!candidates.has(v));candidates.set(v,{proof,next});
  }
  const config={network:genesis,height:s.sequence+1,previousRoot:s.root,authorities:structuredClone(witnesses),financialCandidates:[...candidates.keys()].sort()};
  const lab=createPayRoundLab(config);
  return {config,lab,candidates};
 }
 function admissionBytes(d,a){return encode(['quantic-pay-admission-vote/v1',genesis,d.config.height,d.config.previousRoot,d.lab.scope,a.pin,a.pqPin,true]);}
 function validateAdmissionVote(d,v){
  check(exact(v,['pin','pqPin','signature','pqSignature']));
  const a=authorities.get(v.pin);check(a&&a.pqPin===v.pqPin);
  const bytes=admissionBytes(d,a);
  check(verify(null,bytes,a.classical,decode(v.signature,64))&&verify(null,bytes,a.pq,decode(v.pqSignature,3309)));
  return a.pin;
 }
 function roundAdmission(s,admission){
  if(!gated)return draftAdmission(s,admission);
  check(exact(admission,['proposals','admissionTime','endorsements'])&&Array.isArray(admission.endorsements)&&admission.endorsements.length>=3&&admission.endorsements.length<=4);
  const d=draftAdmission(s,{proposals:admission.proposals,admissionTime:admission.admissionTime}),seen=new Set();
  for(const vote of admission.endorsements){const p=validateAdmissionVote(d,vote);check(!seen.has(p));seen.add(p);}
  return d;
 }
 function applyRound(s,record){
  check(exact(record,['admission','certificate']));
  const {lab,candidates}=roundAdmission(s,record.admission),final=lab.finalized(record.certificate),c=candidates.get(final.value);
  check(c);
  return {next:c.next,receipt:Object.freeze({status:'LAB_CHAIN_COMMITTED',scope:lab.scope,sequence:c.next.sequence,round:final.round,reference:'LAB-'+final.value.slice(0,30),nonce:c.proof.intent.nonce,payer:c.proof.intent.payer,payee:c.proof.intent.payee,cents:c.proof.intent.cents,root:c.next.root,simulationOnly:true,realPaymentAuthorized:false,settlementVerified:false})};
 }
 function replay(records){
  check(Array.isArray(records)&&records.length<=(multiRound?32:256));
  let s=empty();for(const record of records)s=multiRound?applyRound(s,record).next:apply(s,record);return s;
 }
 function snapshot(records){const s=replay(records);return Object.freeze({network:genesis,sequence:s.sequence,root:s.root,balances:Object.freeze(s.balances),totalCents:total,simulationOnly:true,redeemable:false});}
 function prepare(records,{payer,payee,cents,nonce,now=Date.now()}){
  const s=replay(records),a=accounts.get(payer),b=accounts.get(payee);
  check(a&&b&&Number.isSafeInteger(now)&&now>=0&&now<=Number.MAX_SAFE_INTEGER-120000);
  const i=Object.freeze({network:genesis,sequence:s.sequence+1,previousRoot:s.root,payer,payee,payerPin:a.pin,payerPQPin:a.pqPin,payeePin:b.pin,payeePQPin:b.pqPin,cents,currency:'EUR',nonce,issued:now,expires:now+120000,simulationOnly:true});
  transcript(i);check(s.balances[payer]>=cents&&!s.nonces.has(nonce));return i;
 }
 // A witness independently replays its own retained history. This pure helper
 // does not provide persistent no-equivocation or a network consensus protocol.
 function attest({retainedRecords,proof,decidedAt,authorityPin,classicalPrivateKey,pqPrivateKey,now=Date.now()}){
  const a=authorities.get(authorityPin);check(a&&classicalPrivateKey?.type==='private'&&pqPrivateKey?.type==='private'&&sha(createPublicKey(classicalPrivateKey).export({type:'spki',format:'der'}))===a.pin&&sha(createPublicKey(pqPrivateKey).export({type:'spki',format:'der'}))===a.pqPin);
  const next=advance(replay(retainedRecords),proof);
  check(Number.isSafeInteger(now)&&Number.isSafeInteger(decidedAt)&&now>=decidedAt&&now-decidedAt<=15000&&decidedAt>=proof.intent.issued&&now<proof.intent.expires);
  const msg=voteBytes(proof,next,decidedAt,a);
  return Object.freeze({pin:a.pin,pqPin:a.pqPin,signature:sign(null,msg,classicalPrivateKey).toString('base64url'),pqSignature:sign(null,msg,pqPrivateKey).toString('base64url')});
 }
 function confirm(records,record,now=Date.now()){
  check(Number.isSafeInteger(now)&&now>=record.decidedAt&&now-record.decidedAt<=15000&&now<record.proof.intent.expires);
  const next=apply(replay(records),record);
  return Object.freeze({sequence:next.sequence,root:next.root,balances:Object.freeze(next.balances),totalCents:total,simulationOnly:true,realPaymentAuthorized:false,settlementVerified:false});
 }
 // Validate a retained single vote without signing again or assuming a quorum.
 function inspectVote(records,proof,decidedAt,v){
  const next=advance(replay(records),proof),a=authorities.get(v.pin);
  check(a&&v.pqPin===a.pqPin&&Number.isSafeInteger(decidedAt)&&decidedAt>=proof.intent.issued&&decidedAt<proof.intent.expires);
  const msg=voteBytes(proof,next,decidedAt,a);
  check(verify(null,msg,a.classical,decode(v.signature,64))&&verify(null,msg,a.pq,decode(v.pqSignature,3309)));
  return Object.freeze({digest:verifyProof(proof),sequence:next.sequence,root:next.root});
 }
 // A validated candidate is a hypothetical next state, not a committed
 // ledger entry. No old single-phase quorum is implied.
 function inspectCandidate(records,proof){
  const next=advance(replay(records),proof);
  return Object.freeze({digest:verifyProof(proof),sequence:next.sequence,root:next.root,balances:Object.freeze(next.balances),totalCents:total,simulationOnly:true,committed:false});
 }
 if(multiRound)return Object.freeze({snapshot,prepare,transcript,gated,
  draft(records,admission){
   check(gated);
   const d=draftAdmission(replay(records),structuredClone(admission));
   return Object.freeze({scope:d.lab.scope,height:d.config.height,previousRoot:d.config.previousRoot});
  },
  signAdmission(records,admission,{authorityPin,classicalPrivateKey,pqPrivateKey}){
   check(gated);
   const d=draftAdmission(replay(records),admission),a=authorities.get(authorityPin);
   check(a&&classicalPrivateKey?.type==='private'&&pqPrivateKey?.type==='private'&&sha(createPublicKey(classicalPrivateKey).export({type:'spki',format:'der'}))===a.pin&&sha(createPublicKey(pqPrivateKey).export({type:'spki',format:'der'}))===a.pqPin);
   const msg=admissionBytes(d,a);
   return Object.freeze({pin:a.pin,pqPin:a.pqPin,signature:sign(null,msg,classicalPrivateKey).toString('base64url'),pqSignature:sign(null,msg,pqPrivateKey).toString('base64url')});
  },
  inspectAdmissionVote(records,admission,vote){
   check(gated);return validateAdmissionVote(draftAdmission(replay(records),admission),vote);
  },
  admit(records,admission){
   const {config,lab,candidates}=roundAdmission(replay(records),structuredClone(admission));
   return Object.freeze({scope:lab.scope,config,candidates:[...candidates].map(([value,c])=>({value,payer:c.proof.intent.payer,payee:c.proof.intent.payee,cents:c.proof.intent.cents}))});
  },
  receipt(records,record){return applyRound(replay(records),record).receipt;}
 });
 return Object.freeze({snapshot,prepare,transcript,attest,confirm,inspectVote,inspectCandidate});
}
