// Local in-memory test harness with four separate witness states and keys.
// NO real external authorities, no native vault, no cash, no settlement.
import {generateKeyPairSync,createHash,sign} from 'node:crypto';
import {createPayQuorumFlow} from '../lib/quantic/pay-quorum-flow.mjs';
import {attestPayCheckpoint,summarizePayProofs,verifyHistoricalPayProof} from '../lib/quantic/pay-lab-checkpoint.mjs';
const sha=b=>createHash('sha256').update(b).digest('hex');
const spki=k=>k.publicKey.export({format:'der',type:'spki'});
export function createLocalQuorumDemo({available=()=>[0,1,2,3],initialWitnessProofs,clock=Date.now}={}){
 const ec=generateKeyPairSync('ec',{namedCurve:'prime256v1'}),pq=generateKeyPairSync('ml-dsa-65');
 const scope={signingPin:sha(spki(ec)),pqPin:sha(spki(pq))};
 const classical=ec.publicKey.export({format:'jwk'});
 const point=Buffer.concat([Buffer.from([4]),Buffer.from(classical.x,'base64url'),Buffer.from(classical.y,'base64url')]);
 const signProof=async intent=>{
   const b=Buffer.from(JSON.stringify(['quantic-pay-native-simulation/v1',scope.signingPin,scope.pqPin,intent.Payee,intent.Cents,'EUR',intent.Nonce,intent.Issued,intent.Expires,false]));
   return {intent,...scope,realPaymentAuthorized:false,classicalPublic:point.toString('base64url'),pqPublic:spki(pq).toString('base64url'),classicalSignature:sign('sha256',b,{key:ec.privateKey,dsaEncoding:'ieee-p1363'}).toString('base64url'),pqSignature:sign(null,b,pq.privateKey).toString('base64url')};
  };
 return createLocalWitnessFlow({scope,signProof,available,initialWitnessProofs,clock});
}
// The signing callback can instead be the explicitly approved native Pay vault.
// Witnesses remain ephemeral and local; never initialize them from wallet history.
export function createLocalWitnessFlow({scope,signProof,available=()=>[0,1,2,3],initialWitnessProofs,clock=Date.now}){
 if(typeof signProof!=='function')throw Error('A signer is required');
 scope=Object.freeze({...scope});
 const witnesses=Array.from({length:4},(_,index)=>{
  const k=generateKeyPairSync('ed25519'),wq=generateKeyPairSync('ml-dsa-65');let retained=structuredClone(initialWitnessProofs?.[index]??[]);
  return Object.freeze({trusted:{pin:sha(spki(k)),publicKey:spki(k).toString('base64url'),pqPin:sha(spki(wq)),pqPublicKey:spki(wq).toString('base64url')},
   vote:request=>attestPayCheckpoint({retainedProofs:retained,request,authorityPrivateKey:k.privateKey,authorityPQPrivateKey:wq.privateKey,now:clock()}),
   append(proof,prior){
    const current=summarizePayProofs(retained,scope);
    if(current.count!==prior.count||current.root!==prior.root)throw Error('Witness state mismatch');
    const v=verifyHistoricalPayProof(proof,scope);
    if(retained.some(p=>p.intent.Nonce===v.nonce))throw Error('Duplicate');
    if(clock()<proof.intent.Issued||clock()>=proof.intent.Expires)throw Error('Expired');
    summarizePayProofs([...retained,proof],scope);
    retained=[...retained,structuredClone(proof)];
   }});
 });
 const flow=createPayQuorumFlow({scope,clock,trustedAuthorities:witnesses.map(w=>w.trusted),
  readVotes:async request=>available('read').map(i=>witnesses[i].vote(request)),
  signProof,
  submitProof:async(proof,prior)=>{for(const i of available('append'))witnesses[i].append(proof,prior);}
 });
 return flow;
}
