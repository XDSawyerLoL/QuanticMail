// Synthetic, ephemeral signing demonstration. Not financial authorization.
// No live keys, account identifiers, network, or redeemable payment.
import {generateKeyPairSync,randomBytes,sign,verify,createHash} from 'node:crypto';
import {PAYEES} from './pay-sandbox.mjs';
const check=(v)=>{if(!v)throw Error('Autorisation fictive refusee')};
const digest=b=>createHash('sha256').update(b).digest('hex');
const publicPin=k=>digest(k.export({format:'der',type:'spki'}));
export function createDemoPayAuthorization({clock=Date.now}={}){
 const p256=generateKeyPairSync('ec',{namedCurve:'prime256v1'});
 const pq=generateKeyPairSync('ml-dsa-65');
 const session=randomBytes(32).toString('hex');
 const keyPins=Object.freeze([publicPin(p256.publicKey),publicPin(pq.publicKey)]);
 const issued=new Map();
 function transcript(intent,challenge){
  check(intent?.status==='prepared'&&intent.realPayment===false&&intent.currency==='EUR');
  check(typeof intent.id==='string'&&/^DEMO-[0-9]{6}$/.test(intent.id));
  check(PAYEES.some(p=>p.id===intent.payeeId)&&Number.isSafeInteger(intent.cents)&&intent.cents>=1&&intent.cents<=10000);
  check(Number.isSafeInteger(intent.createdAt)&&intent.createdAt>=0&&intent.expiresAt===intent.createdAt+120000);
  check(typeof challenge==='string'&&/^[a-f0-9]{64}$/.test(challenge));
  return Buffer.from(JSON.stringify(['quantic-pay-simulation-authorization/v1',session,...keyPins,intent.id,intent.payeeId,intent.cents,intent.currency,intent.createdAt,intent.expiresAt,challenge,false]));
 }
 function fresh(i){const n=clock();check(Number.isSafeInteger(n)&&n>=i.createdAt&&n<i.expiresAt);}
 function verifyProof(intent,proof){
  try{
   fresh(intent);check(proof?.simulationOnly===true&&typeof proof.challenge==='string');
   const b=transcript(intent,proof.challenge);check(proof.digest===digest(b));
   const state=issued.get(intent.id);check(state&&state.challenge===proof.challenge&&state.digest===proof.digest);
   const a=Buffer.from(proof.p256,'base64url'),q=Buffer.from(proof.mlDsa65,'base64url');
   check(a.length===64&&q.length===3309&&a.toString('base64url')===proof.p256&&q.toString('base64url')===proof.mlDsa65);
   return verify('sha256',b,{key:p256.publicKey,dsaEncoding:'ieee-p1363'},a)&&verify(null,b,pq.publicKey,q);
  }catch{return false;}
 }
 return Object.freeze({
  keyPins,
  authorize(intent,explicitConsent){
   check(explicitConsent===true&&!issued.has(intent?.id)&&issued.size<100);
   fresh(intent);const challenge=randomBytes(32).toString('hex'),b=transcript(intent,challenge),d=digest(b);
   const proof=Object.freeze({simulationOnly:true,challenge,digest:d,p256:sign('sha256',b,{key:p256.privateKey,dsaEncoding:'ieee-p1363'}).toString('base64url'),mlDsa65:sign(null,b,pq.privateKey).toString('base64url')});
   issued.set(intent.id,{challenge,digest:d,consumed:false});
   check(verifyProof(intent,proof));return proof;
  },
  verifyProof,
  consume(intent,proof){
   check(verifyProof(intent,proof));
   const state=issued.get(intent.id);check(!state.consumed);state.consumed=true;
   return Object.freeze({simulationOnly:true,verified:true,authorizationDigest:proof.digest,realPaymentAuthorized:false});
  }
 });
}
