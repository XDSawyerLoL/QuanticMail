// Offline dictionary projection only. NOT a valid ISO 20022 message, DESP API,
// payment instruction, real PSP adapter, SCA credential or settlement record.
import {createHash} from 'node:crypto';
import {payEuropeanReadiness} from './pay-eu-readiness.mjs';
import {reconcilePayCheckpoint,verifyHistoricalPayProof} from './pay-lab-checkpoint.mjs';
const check=v=>{if(!v)throw Error('Pay interoperability preview refused');};
const sha=b=>createHash('sha256').update(b).digest('hex');
export function previewPayDictionary({localProofs,nonce,request,trustedAuthorities,attestations,now=Date.now()}){
 check(typeof nonce==='string'&&/^[a-f0-9]{64}$/.test(nonce));
 const quorum=reconcilePayCheckpoint({localProofs,request,trustedAuthorities,attestations,now});
 const matches=localProofs.filter(p=>p.intent.Nonce===nonce);check(matches.length===1);
 const p=matches[0],verified=verifyHistoricalPayProof(p,request);
 const reference='LAB-'+sha(Buffer.from(JSON.stringify(['quantic-pay-preview/v1',verified.digest]))).slice(0,30);
 const cents=verified.cents,amount=String(Math.floor(cents/100))+'.'+String(cents%100).padStart(2,'0');
 return Object.freeze({
  format:'quantic-pay-iso20022-dictionary-preview/v1',
  environment:'offline-simulation',transmittable:false,realPaymentAuthorized:false,settlementVerified:false,
  referenceModel:'ISO 20022 payments initiation data concepts',
  paymentIdentification:Object.freeze({endToEndIdentification:reference}),
  instructedAmount:Object.freeze({value:amount,currency:'EUR'}),
  creditor:Object.freeze({name:p.intent.Payee==='demo-shop'?'LAB DEMO MERCHANT':'LAB DEMO PERSON',simulationOnly:true}),
  initiationTime:new Date(verified.issued).toISOString(),
  evidence:Object.freeze({intentDigest:verified.digest,proofSetRoot:quorum.root,proofCount:quorum.proofCount,witnessCount:quorum.witnessCount}),
  status:'LAB_QUORUM_MATCHED_NOT_SETTLED'
 });
}
// Explicit boundary: no network, XML, IBAN, credentials or live provider.
export function createDigitalEuroLabAdapter(){
 return Object.freeze({
  capabilities:()=>Object.freeze({environment:'offline-simulation',providerConnected:false,officialSchemaValidated:false,despConnected:false,realPaymentAuthorized:false}),
  readiness:payEuropeanReadiness,
  preview:previewPayDictionary,
  submit(){throw Error('No authorized PSP or official digital euro interface configured');},
  settle(){throw Error('Laboratory cannot settle money');}
 });
}
