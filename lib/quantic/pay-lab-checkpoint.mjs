// Read-only fictional transaction reconciliation against four independent
// trusted witness keys. No live payment, registry write, or witness service.
import {createHash,createPublicKey,sign,verify,randomBytes} from 'node:crypto';
const check=v=>{if(!v)throw Error('Pay laboratory checkpoint refused');};
const hex=/^[a-f0-9]{64}$/;
const sha=b=>createHash('sha256').update(b).digest('hex');
const spki=k=>k.export({type:'spki',format:'der'});
const pin=k=>sha(spki(k));
const pins=(s,d)=>{check(typeof s==='string'&&hex.test(s)&&typeof d==='string'&&hex.test(d)&&s!==d);};
function decode(v,n){
 check(typeof v==='string'&&v.length===Math.ceil(n*8/6)&&/^[A-Za-z0-9_-]+$/.test(v));
 const b=Buffer.from(v,'base64url');check(b.length===n&&b.toString('base64url')===v);return b;
}
export function verifyHistoricalPayProof(p,{signingPin:s,pqPin:d}){
 pins(s,d);
 const i=p?.intent;
 check(p?.realPaymentAuthorized===false&&p.signingPin===s&&p.pqPin===d);
 check(i&&['demo-shop','demo-person'].includes(i.Payee)&&Number.isSafeInteger(i.Cents)&&i.Cents>=1&&i.Cents<=10000);
 check(typeof i.Nonce==='string'&&hex.test(i.Nonce)&&Number.isSafeInteger(i.Issued)&&i.Issued>=0&&Number.isSafeInteger(i.Expires)&&i.Expires-i.Issued===120000);
 const point=decode(p.classicalPublic,65);check(point[0]===4);
 const ec=createPublicKey({key:{kty:'EC',crv:'P-256',x:point.subarray(1,33).toString('base64url'),y:point.subarray(33).toString('base64url')},format:'jwk'});
 const der=decode(p.pqPublic,1974),pq=createPublicKey({key:der,format:'der',type:'spki'});
 check(pin(ec)===s&&sha(der)===d&&pq.asymmetricKeyType==='ml-dsa-65'&&spki(pq).equals(der));
 const b=Buffer.from(JSON.stringify(['quantic-pay-native-simulation/v1',s,d,i.Payee,i.Cents,'EUR',i.Nonce,i.Issued,i.Expires,false]));
 const cl=decode(p.classicalSignature,64),ds=decode(p.pqSignature,3309);
 check(verify('sha256',b,{key:ec,dsaEncoding:'ieee-p1363'},cl)&&verify(null,b,pq,ds));
 // Commit the canonical intent rather than randomized signature bytes.
 return Object.freeze({nonce:i.Nonce,digest:sha(b),cents:i.Cents,issued:i.Issued});
}
export function summarizePayProofs(proofs,scope){
 pins(scope.signingPin,scope.pqPin);
 check(Array.isArray(proofs)&&proofs.length<=1000);
 const seen=new Set(),records=[];
 for(const p of proofs){
  const r=verifyHistoricalPayProof(p,scope);check(!seen.has(r.nonce));seen.add(r.nonce);records.push(r);
 }
 records.sort((a,b)=>a.nonce<b.nonce?-1:a.nonce>b.nonce?1:0);
 return Object.freeze({signingPin:scope.signingPin,pqPin:scope.pqPin,count:records.length,root:sha(Buffer.from(JSON.stringify(['quantic-pay-lab-proof-set/v1',scope.signingPin,scope.pqPin,records.map(r=>[r.nonce,r.digest])]))),simulationOnly:true});
}
export function newPayCheckpointRequest(scope,now=Date.now()){
 pins(scope.signingPin,scope.pqPin);check(Number.isSafeInteger(now)&&now>=0&&now<=Number.MAX_SAFE_INTEGER-15000);
 return Object.freeze({signingPin:scope.signingPin,pqPin:scope.pqPin,nonce:randomBytes(32).toString('hex'),expires:now+15000});
}
function requestValid(r,now){
 check(Number.isSafeInteger(now)&&now>=0&&r&&typeof r.nonce==='string'&&hex.test(r.nonce)&&Number.isSafeInteger(r.expires)&&r.expires>now&&r.expires-now<=15000);
 pins(r.signingPin,r.pqPin);
}
function payloadBytes(p){
 check(p?.simulationOnly===true&&Number.isSafeInteger(p.count)&&p.count>=0&&p.count<=1000&&typeof p.root==='string'&&hex.test(p.root));
 pins(p.signingPin,p.pqPin);
 return Buffer.from(JSON.stringify(['quantic-pay-lab-checkpoint/v1',p.signingPin,p.pqPin,p.count,p.root,p.nonce,p.expires,true]));
}
// Each authority must use its OWN independently retained proof set. Never sign
// a root supplied by the requesting wallet. Actual remote custody not included.
export function attestPayCheckpoint({retainedProofs,request,authorityPrivateKey,now=Date.now()}){
 requestValid(request,now);
 check(authorityPrivateKey?.type==='private'&&authorityPrivateKey.asymmetricKeyType==='ed25519');
 const v=summarizePayProofs(retainedProofs,request);
 const payload=Object.freeze({...v,nonce:request.nonce,expires:request.expires});
 return Object.freeze({authorityPin:pin(createPublicKey(authorityPrivateKey)),payload,signature:sign(null,payloadBytes(payload),authorityPrivateKey).toString('base64url')});
}
export function reconcilePayCheckpoint({localProofs,request,trustedAuthorities,attestations,now=Date.now()}){
 requestValid(request,now);check(Array.isArray(trustedAuthorities)&&trustedAuthorities.length===4&&Array.isArray(attestations)&&attestations.length<=4);
 const keys=new Map();
 for(const t of trustedAuthorities){
  const der=decode(t.publicKey,44),k=createPublicKey({key:der,type:'spki',format:'der'});
  check(k.asymmetricKeyType==='ed25519'&&spki(k).equals(der)&&pin(k)===t.pin&&!keys.has(t.pin));keys.set(t.pin,k);
 }
 const groups=new Map(),seen=new Set();
 for(const a of attestations){
  try{
   check(a&&keys.has(a.authorityPin)&&!seen.has(a.authorityPin));
   const p=a.payload;
   check(p.signingPin===request.signingPin&&p.pqPin===request.pqPin&&p.nonce===request.nonce&&p.expires===request.expires);
   const raw=payloadBytes(p);
   check(verify(null,raw,keys.get(a.authorityPin),decode(a.signature,64)));
   seen.add(a.authorityPin);
   const id=sha(raw),g=groups.get(id)??{p,count:0};g.count++;groups.set(id,g);
  }catch{/* Invalid votes never count. */}
 }
 const quorum=[...groups.values()].find(g=>g.count>=3);check(quorum);
 const local=summarizePayProofs(localProofs,request);
 check(local.count===quorum.p.count&&local.root===quorum.p.root);
 return Object.freeze({verified:true,simulationOnly:true,proofCount:local.count,root:local.root,witnessCount:quorum.count,realPaymentAuthorized:false,settlementVerified:false});
}
