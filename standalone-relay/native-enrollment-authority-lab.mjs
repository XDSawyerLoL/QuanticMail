// Private laboratory transport: one independently preapproved candidate per
// authority. No public enrollment endpoint, bearer token, or policy activation.
import {createServer} from 'node:https';
import {createHash,sign} from 'node:crypto';
import {createNativeEnrollmentRegistryLab,verifyNativeEnrollmentReceipts} from '../lib/quantic/native-enrollment-registry-lab.mjs';
import {issueNativePossessionChallenge} from '../lib/quantic/native-possession-challenge.mjs';
const check=x=>{if(!x)throw Error('Native enrollment transport refused');};
const sha=b=>createHash('sha256').update(b).digest('hex');
const hex=/^[a-f0-9]{64}$/;
const exact=(o,keys)=>check(o&&typeof o==='object'&&!Array.isArray(o)&&Object.keys(o).length===keys.length&&keys.every(k=>Object.hasOwn(o,k)));
import {authFormat,authBytes} from '../lib/quantic/native-authentication-receipt-lab.mjs';
export {verifyNativeAuthenticationQuorum} from '../lib/quantic/native-authentication-receipt-lab.mjs';
export async function startNativeEnrollmentAuthorityLab({directory,authorityKey,authorityPin,tls,clientPin,candidate,expected,trusted,port=0,labOnly,operatorApproved}){
 check(labOnly===true&&operatorApproved===true&&hex.test(clientPin)&&Number.isInteger(port)&&port>=0&&port<=65535);
 const snapshot=structuredClone(candidate),pins=structuredClone(expected),trust=structuredClone(trusted);
 check(Array.isArray(trust)&&trust.length===4&&trust.some(t=>t.pin===authorityPin));
 const registry=await createNativeEnrollmentRegistryLab({directory,authorityKey,authorityPin,labOnly:true});
 let pending=null,busy=false,attempts=0,windowStart=Date.now(),timer;
 function clearPending(){
  clearTimeout(timer);pending?.proof.close();pending=null;
 }
 function stage(kind,proof,nonce){
  check(!pending);
  pending={kind,proof,nonce};timer=setTimeout(clearPending,Math.max(1,proof.expires-Date.now()));timer.unref();
  return {challenge:proof.challenge,challengeSha256:proof.challengeSha256,expires:proof.expires};
 }
 const server=createServer({...tls,minVersion:'TLSv1.3',requestCert:true,rejectUnauthorized:true},async(req,res)=>{
  const reply=(code,body)=>{
   if(res.destroyed||res.writableEnded)return;
   const bytes=Buffer.from(JSON.stringify(body));
   res.writeHead(code,{'Content-Type':'application/json','Content-Length':bytes.length,'Cache-Control':'no-store','Connection':'close'});res.end(bytes);
  };
  let entered=false;
  try{
   const cert=req.socket.getPeerCertificate();
   check(req.socket.authorized&&cert?.raw&&sha(cert.raw)===clientPin&&req.method==='POST'&&req.headers['content-type']==='application/json'&&!req.headers['transfer-encoding']);
   check(!busy);busy=true;entered=true;
   const now=Date.now();if(now-windowStart>=60000){attempts=0;windowStart=now;}
   check(++attempts<=30);
   const length=Number(req.headers['content-length']);check(Number.isSafeInteger(length)&&length>=2&&length<=32768);
   let n=0;const chunks=[];for await(const c of req){n+=c.length;check(n<=length);chunks.push(c);}check(n===length);
   const body=JSON.parse(Buffer.concat(chunks).toString('utf8'));
   if(pending&&Date.now()>=pending.proof.expires)clearPending();
   switch(req.url){
    case '/native-enrollment/begin':{
     exact(body,[]);check(!pending);
     reply(200,stage('enroll',await registry.begin(snapshot,pins,{operatorApproved:true})));break;
    }
    case '/native-enrollment/readback':{
     exact(body,[]);reply(200,await registry.readback(snapshot,pins));break;
    }
    case '/native-authentication/begin':{
     exact(body,['nonce','enrollmentReceipts']);check(!pending&&typeof body.nonce==='string'&&hex.test(body.nonce));
     verifyNativeEnrollmentReceipts(body.enrollmentReceipts,trust,snapshot,pins);
     await registry.readback(snapshot,pins);
     reply(200,stage('auth',issueNativePossessionChallenge(snapshot,pins),body.nonce));break;
    }
    case '/native-enrollment/finish':
    case '/native-authentication/finish':{
     exact(body,['response']);
     const kind=req.url.includes('authentication')?'auth':'enroll';
     check(pending?.kind===kind);
     const job=pending;pending=null;clearTimeout(timer);
     try{
      if(kind==='enroll'){reply(200,await job.proof.commit(body.response));break;}
      const proof=job.proof.verify(body.response);
      await registry.readback(snapshot,pins);
      const issuedAt=Date.now();
      check(proof.devicePossessionVerified===true&&issuedAt<job.proof.expires);
      const r={format:authFormat,authorityPin,address:pins.address,deviceId:pins.deviceId,candidateDigest:proof.candidateDigest,clientPin,nonce:job.nonce,challengeSha256:job.proof.challengeSha256,issuedAt,expires:issuedAt+15000,signature:''};
      r.signature=sign(null,authBytes(r),authorityKey).toString('base64url');reply(200,r);
     }finally{job.proof.close();}
     break;
    }
    default:throw Error('Unknown operation');
   }
  }catch{reply(403,{error:'native authority refused'});}
  finally{if(entered)busy=false;}
 });
 server.requestTimeout=5000;server.headersTimeout=3000;server.keepAliveTimeout=1000;server.maxRequestsPerSocket=1;server.maxConnections=8;
 server.setTimeout(6000,s=>s.destroy());
 await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(port,'127.0.0.1',resolve);});
 return Object.freeze({port:server.address().port,close:()=>new Promise((resolve,reject)=>{clearPending();server.close(e=>e?reject(e):resolve());server.closeAllConnections();})});
}
