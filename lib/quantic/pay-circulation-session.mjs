// Local synthetic user journey. Ephemeral test identities and witness keys;
// NOT the native wallet, a PSP, independent hosts or persistent consensus.
import {createHash,generateKeyPairSync,sign,randomBytes} from 'node:crypto';
import {createCirculationLab} from './pay-circulation-lab.mjs';
import {recoverCirculationCertificate} from './pay-circulation-recovery.mjs';
const check=v=>{if(!v)throw Error('Circulation session refused');};
const sha=b=>createHash('sha256').update(b).digest('hex');
const spki=k=>k.publicKey.export({type:'spki',format:'der'});
function pair(type){return {cl:type==='ec'?generateKeyPairSync('ec',{namedCurve:'prime256v1'}):generateKeyPairSync(type),pq:generateKeyPairSync('ml-dsa-65')};}
const pub=k=>({pin:sha(spki(k.cl)),publicKey:spki(k.cl).toString('base64url'),pqPin:sha(spki(k.pq)),pqPublicKey:spki(k.pq).toString('base64url')});
export const DEMO_WALLETS=Object.freeze(['demo-alice','demo-bob','demo-shop']);
export function createCirculationSession({clock=Date.now}={}){
 const keys=DEMO_WALLETS.map(()=>pair('ec')),witnesses=Array.from({length:4},()=>pair('ed25519'));
 const config={wallets:DEMO_WALLETS.map((id,i)=>({id,initialCents:i===0?10000:0,...pub(keys[i])})),witnesses:witnesses.map(pub)};
 const lab=createCirculationLab(config),records=[],retained=witnesses.map(()=>[]);
 let available=[0,1,2,3],pending=null,blocked=false;
 const snapshot=()=>Object.freeze({...lab.snapshot(records),availableWitnesses:available.length,pending:pending?Object.freeze({...pending}):null,blocked,persistent:false,realPaymentAuthorized:false});
 function setAvailability(indices){
  check(!pending&&!blocked&&Array.isArray(indices)&&indices.length<=4&&new Set(indices).size===indices.length&&indices.every(i=>Number.isInteger(i)&&i>=0&&i<4));
  available=[...indices].sort((a,b)=>a-b);return snapshot();
 }
 function prepare({payer,payee,cents}){
  check(!blocked&&!pending&&available.length>=3);
  pending=lab.prepare(records,{payer,payee,cents,nonce:randomBytes(32).toString('hex'),now:clock()});
  return Object.freeze({...pending});
 }
 function confirm({nonce,explicitConsent}){
  check(!blocked&&pending&&nonce===pending.nonce&&explicitConsent===true&&available.length>=3);
  const intent=pending,now=clock();pending=null;
  check(Number.isSafeInteger(now)&&now>=intent.issued&&now<intent.expires);
  const k=keys[DEMO_WALLETS.indexOf(intent.payer)],raw=lab.transcript(intent);
  const proof={intent,signature:sign('sha256',raw,{key:k.cl.privateKey,dsaEncoding:'ieee-p1363'}).toString('base64url'),pqSignature:sign(null,raw,k.pq.privateKey).toString('base64url')};
  try{
   const reports=available.map(i=>{
    const w=witnesses[i],a=config.witnesses[i];
    const vote=lab.attest({retainedRecords:retained[i],proof,decidedAt:now,authorityPin:a.pin,classicalPrivateKey:w.cl.privateKey,pqPrivateKey:w.pq.privateKey,now:clock()});
    return {proof,decidedAt:now,vote};
   });
   const recovery=recoverCirculationCertificate({config,records,reports});check(recovery.state==='certificate-recovered');
   const result=lab.confirm(records,recovery.certificate,clock());
   records.push(structuredClone(recovery.certificate));
   // Replicate verified certificate history in memory to each local witness.
   // Availability toggle models voting availability, not transport failures.
   for(const h of retained)h.push(structuredClone(recovery.certificate));
   return Object.freeze({reference:'LAB-'+sha(raw).slice(0,30),sequence:result.sequence,payer:intent.payer,payee:intent.payee,cents:intent.cents,currency:'EUR',witnessCount:reports.length,status:'LAB_QUORUM_CONFIRMED',simulationOnly:true,realPaymentAuthorized:false,settlementVerified:false});
  }catch(e){blocked=true;throw e;}
 }
 function cancel(nonce){check(pending&&pending.nonce===nonce);pending=null;}
 function history(){
  // No private keys, raw signatures or full witness reports in the UI.
  lab.snapshot(records);
  return records.map(r=>Object.freeze({reference:'LAB-'+sha(lab.transcript(r.proof.intent)).slice(0,30),sequence:r.proof.intent.sequence,payer:r.proof.intent.payer,payee:r.proof.intent.payee,cents:r.proof.intent.cents,currency:'EUR',status:'LAB_QUORUM_CONFIRMED',simulationOnly:true}));
 }
 return Object.freeze({snapshot,setAvailability,prepare,confirm,cancel,history});
}
