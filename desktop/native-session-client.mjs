// Local trusted controller, no renderer IPC or browser bearer token.
import {createHash,X509Certificate} from 'node:crypto';
import {nativeAuthorityRequest,runNativeEnrollmentAuthorityClient} from './native-enrollment-authority-client.mjs';
import {createWindowsEnrollmentProver} from './native-windows-enrollment-prover.mjs';
import {watchWindowsSessionLifetime} from './native-windows-session-lifetime.mjs';
const check=x=>{if(!x)throw Error('Native user session refused');};
const hex=/^[a-f0-9]{64}$/;
const sha=b=>createHash('sha256').update(b).digest('hex');
export function createNativeSessionClientLab({service,authorities,tls,candidate,expected,enrollmentReceipts,clientPin,prove,labOnly}){
 check(labOnly===true&&typeof prove==='function'&&typeof clientPin==='string'&&hex.test(clientPin)&&sha(new X509Certificate(tls.cert).raw)===clientPin);
 const target=structuredClone(service),trust=structuredClone(authorities),identity=structuredClone(candidate),pins=structuredClone(expected),receipts=structuredClone(enrollmentReceipts);
 check(typeof target.tlsPin==='string'&&hex.test(target.tlsPin)&&trust.every(a=>a.tlsPin!==target.tlsPin&&new URL(a.url).origin!==new URL(target.url).origin));
 const call=(op,body)=>nativeAuthorityRequest(target,tls,'/native-session/'+op,body);
 let active=null,generation=0,opening=false;
 function live(){
  if(active&&Date.now()>=active.expires)active=null;
  return active;
 }
 async function lock(){
  ++generation;const current=active;active=null;
  if(!current)return {localLocked:true,remoteLockConfirmed:false};
  try{
   const r=await call('lock',{sessionId:current.sessionId});
   return {localLocked:true,remoteLockConfirmed:r?.status==='native-session-locked-lab'};
  }catch{return {localLocked:true,remoteLockConfirmed:false};}
 }
 async function login(){
  check(!opening&&!live());opening=true;
  const epoch=++generation;let ch,opened;
  try{
   ch=await call('begin',{});
   check(ch&&Object.keys(ch).length===2&&typeof ch.nonce==='string'&&hex.test(ch.nonce)&&Number.isSafeInteger(ch.expires)&&ch.expires>Date.now()&&ch.expires<=Date.now()+180000);
   check(generation===epoch);
   const a=await runNativeEnrollmentAuthorityClient({authorities:trust,tls,candidate:identity,expected:pins,enrollmentReceipts:receipts,clientPin,mode:'authenticate',authenticationNonce:ch.nonce,prove:async(...args)=>{check(generation===epoch);return prove(...args);}});
   check(generation===epoch&&a.result.nonce===ch.nonce);
   opened=await call('open',{nonce:ch.nonce,receipts:a.receipts});
   check(opened?.status==='native-session-open-lab'&&opened.labOnly===true&&opened.productionAuthorized===false&&typeof opened.sessionId==='string'&&hex.test(opened.sessionId)&&opened.address===pins.address&&opened.deviceId===pins.deviceId&&Number.isSafeInteger(opened.issuedAt)&&opened.expires===opened.issuedAt+60000&&opened.expires>Date.now()&&opened.expires<=Date.now()+60000);
   check(generation===epoch);
   active=Object.freeze({...opened});
   return Object.freeze({status:active.status,address:active.address,deviceId:active.deviceId,expires:active.expires,labOnly:true});
  }catch(e){
   // Lock during login must not leave a late reply opening the local client.
   if(opened?.sessionId&&hex.test(opened.sessionId))await call('lock',{sessionId:opened.sessionId}).catch(()=>{});
   else if(ch?.nonce&&hex.test(ch.nonce))await call('cancel',{nonce:ch.nonce}).catch(()=>{});
   throw e;
  }finally{opening=false;}
 }
 async function whoami(){
  const s=live(),epoch=generation;check(s);
  try{
   const r=await call('whoami',{sessionId:s.sessionId});
   check(generation===epoch&&live()===s&&r?.status==='native-session-authenticated-lab'&&r.address===pins.address&&r.deviceId===pins.deviceId&&r.expires===s.expires&&r.productionAuthorized===false);
   return Object.freeze(r);
  }catch(e){if(active===s)active=null;throw e;}
 }
 return Object.freeze({login,whoami,lock,isUnlocked:()=>Boolean(live())});
}
export async function createWindowsNativeSessionClientLab(config){
 const prove=await createWindowsEnrollmentProver(config);
 return watchWindowsSessionLifetime(config,createNativeSessionClientLab({...config,prove}));
}
