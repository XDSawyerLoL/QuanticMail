// Trusted lab client. Only pinned mTLS authorities, no redirects or fallback.
import {request} from 'node:https';
import {checkServerIdentity} from 'node:tls';
import {createHash,randomBytes} from 'node:crypto';
import {verifyNativeEnrollmentReceipts} from '../lib/quantic/native-enrollment-registry-lab.mjs';
import {verifyNativeAuthenticationQuorum} from '../standalone-relay/native-enrollment-authority-lab.mjs';
const sha=b=>createHash('sha256').update(b).digest('hex');
const check=x=>{if(!x)throw Error('Native authority client refused');};
const hex=/^[a-f0-9]{64}$/;
export function nativeAuthorityRequest(authority,tls,path,body){
 const u=new URL(authority.url);
 check(u.protocol==='https:'&&u.pathname==='/'&&!u.username&&!u.password&&!u.search&&!u.hash&&hex.test(authority.tlsPin));
 check(/^\/native-(enrollment|authentication)\/(begin|finish|readback)$/.test(path));
 const bytes=Buffer.from(JSON.stringify(body));check(bytes.length<=32768);
 return new Promise((resolve,reject)=>{
  const req=request(new URL(path,u),{ca:tls.ca,cert:tls.cert,key:tls.key,agent:false,minVersion:'TLSv1.3',rejectUnauthorized:true,
   checkServerIdentity(host,cert){return checkServerIdentity(host,cert)||(!cert.raw||sha(cert.raw)!==authority.tlsPin?Error('TLS pin refused'):undefined);},
   method:'POST',headers:{'Content-Type':'application/json','Content-Length':bytes.length,'Connection':'close'}},res=>{
    const len=Number(res.headers['content-length']);
    if(res.statusCode!==200||res.headers['transfer-encoding']||!Number.isInteger(len)||len<2||len>32768){res.destroy();reject(Error('Authority refused'));return;}
    let n=0;const chunks=[];
    res.on('data',c=>{n+=c.length;if(n>len)res.destroy(Error('oversize authority response'));else chunks.push(c);});
    res.on('error',reject);res.on('end',()=>{try{check(n===len);resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));}catch(e){reject(e);}});
   });
  const timer=setTimeout(()=>req.destroy(Error('Authority deadline')),6000);
  req.on('close',()=>clearTimeout(timer));req.on('error',reject);req.end(bytes);
 });
}
function validateChallenge(ch,candidate,expected){
 check(ch&&Object.keys(ch).length===3&&typeof ch.challenge==='string'&&Buffer.byteLength(ch.challenge)<=4096&&sha(ch.challenge)===ch.challengeSha256&&Number.isSafeInteger(ch.expires)&&ch.expires>Date.now()&&ch.expires<=Date.now()+180000);
 const a=JSON.parse(ch.challenge);
 check(Array.isArray(a)&&a.length===14&&JSON.stringify(a)===ch.challenge&&a[0]==='quantic-native-enrollment-possession-lab/v1'&&a[9]===sha(JSON.stringify(candidate))&&a[11]===ch.expires);
 const names=['address','deviceId','signingPin','encryptionPin','kemPin','dsaPin','quorumPin','controllerPublic'];
 check(names.every((k,i)=>a[i+1]===expected[k]));
}
export async function runNativeEnrollmentAuthorityClient({authorities,tls,candidate,expected,prove,mode,enrollmentReceipts,clientPin}){
 check(Array.isArray(authorities)&&authorities.length===4&&new Set(authorities.map(a=>a.pin)).size===4&&new Set(authorities.map(a=>a.tlsPin)).size===4&&new Set(authorities.map(a=>new URL(a.url).origin)).size===4);
 check(typeof prove==='function'&&['enroll','authenticate'].includes(mode)&&hex.test(clientPin));
 const auth=mode==='authenticate',nonce=auth?randomBytes(32).toString('hex'):undefined;
 if(auth)verifyNativeEnrollmentReceipts(enrollmentReceipts,authorities,candidate,expected);
 const receipts=[],errors=[];
 for(const a of authorities){
  try{
   // On enrollment, recover only an already committed signed receipt; a
   // failed finish is never silently retried as a new proof.
   if(!auth){
    try{receipts.push(await nativeAuthorityRequest(a,tls,'/native-enrollment/readback',{}));continue;}catch{}
   }
   const prefix=auth?'/native-authentication':'/native-enrollment';
   const ch=await nativeAuthorityRequest(a,tls,prefix+'/begin',auth?{nonce,enrollmentReceipts}:{});
   validateChallenge(ch,candidate,expected);
   const response=await prove(ch,a);
   check(response?.challengeSha256===ch.challengeSha256);
   const r=await nativeAuthorityRequest(a,tls,prefix+'/finish',{response});
   receipts.push(r);
  }catch{errors.push(a.pin);}
 }
 const result=auth?verifyNativeAuthenticationQuorum({receipts,trusted:authorities,candidate,expected,clientPin,nonce}):verifyNativeEnrollmentReceipts(receipts,authorities,candidate,expected);
 return {result,receipts,unavailableAuthorityPins:errors};
}
