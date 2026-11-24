// Explicit private laboratory relying party. A session is server-side,
// certificate-bound, memory-only and capped at 60 seconds. It authorizes
// only the synthetic whoami operation, NOT production mail or payment.
import {createServer} from 'node:https';
import {createHash,randomBytes} from 'node:crypto';
import {verifyNativeEnrollmentReceipts} from '../lib/quantic/native-enrollment-registry-lab.mjs';
import {verifyNativeAuthenticationQuorum} from '../lib/quantic/native-authentication-receipt-lab.mjs';
const check=x=>{if(!x)throw Error('Native session refused');};
const sha=b=>createHash('sha256').update(b).digest('hex');
const hex=/^[a-f0-9]{64}$/;
const exact=(o,keys)=>check(o&&typeof o==='object'&&!Array.isArray(o)&&Object.keys(o).length===keys.length&&keys.every(k=>Object.hasOwn(o,k)));
export function createNativeSessionStateLab({candidate,expected,trusted,clientPin,enrollmentReceipts,allowInitialEnrollment=false,clock=Date.now,labOnly}){
 check(labOnly===true&&typeof clientPin==='string'&&hex.test(clientPin));
 const c=structuredClone(candidate),pins=structuredClone(expected),trust=structuredClone(trusted);
 check(Array.isArray(enrollmentReceipts));
 const initial=allowInitialEnrollment===true&&enrollmentReceipts.length===0;
 if(!initial)verifyNativeEnrollmentReceipts(structuredClone(enrollmentReceipts),trust,c,pins);
 let pending=null,session=null,last=0,closed=false;
 function time(){
  check(!closed);
  const now=clock();
  if(!Number.isSafeInteger(now)||now<last){pending=null;session=null;closed=true;throw Error('Clock rollback');}
  last=now;
  if(pending&&now>=pending.expires)pending=null;
  if(session&&now>=session.expires)session=null;
  return now;
 }
 function guard(peer){check(peer===clientPin);return time();}
 function begin(peer,submittedReceipts){
  const now=guard(peer);
  check(!session&&!pending);
  if(initial||submittedReceipts!==undefined)verifyNativeEnrollmentReceipts(submittedReceipts,trust,c,pins);
  pending={nonce:randomBytes(32).toString('hex'),expires:now+180000};
  return {...pending};
 }
 function open(peer,{nonce,receipts}){
  const now=guard(peer);
  check(!session&&pending&&pending.nonce===nonce);
  // Consume before verification, even for an invalid or incomplete quorum.
  pending=null;
  const result=verifyNativeAuthenticationQuorum({receipts,trusted:trust,candidate:c,expected:pins,clientPin,nonce,now});
  check(result.authorityCount>=3);
  session={sessionId:randomBytes(32).toString('hex'),address:pins.address,deviceId:pins.deviceId,issuedAt:now,expires:now+60000};
  return {status:'native-session-open-lab',...session,labOnly:true,productionAuthorized:false};
 }
 function whoami(peer,id){
  guard(peer);check(session&&typeof id==='string'&&id===session.sessionId);
  return {status:'native-session-authenticated-lab',address:session.address,deviceId:session.deviceId,expires:session.expires,labOnly:true,productionAuthorized:false};
 }
 function lock(peer,id){
  guard(peer);check(session&&id===session.sessionId);
  session=null;
  return {status:'native-session-locked-lab',labOnly:true};
 }
 function cancel(peer,nonce){
  guard(peer);check(pending&&nonce===pending.nonce);pending=null;
  return {status:'native-session-challenge-cancelled-lab',labOnly:true};
 }
 return Object.freeze({begin,open,whoami,lock,cancel,close(){closed=true;pending=null;session=null;}});
}
export async function startNativeSessionServiceLab({tls,port=0,...config}){
 check(Number.isInteger(port)&&port>=0&&port<=65535);
 const state=createNativeSessionStateLab(config);
 let busy=false,attempts=0,windowStart=Date.now();
 const server=createServer({...tls,minVersion:'TLSv1.3',requestCert:true,rejectUnauthorized:true},async(req,res)=>{
  const reply=(code,body)=>{
   if(res.destroyed||res.writableEnded)return;
   const bytes=Buffer.from(JSON.stringify(body));
   res.writeHead(code,{'Content-Type':'application/json','Content-Length':bytes.length,'Cache-Control':'no-store','Connection':'close'});res.end(bytes);
  };
  let entered=false;
  try{
   const cert=req.socket.getPeerCertificate();
   check(req.socket.authorized&&cert?.raw&&sha(cert.raw)===config.clientPin&&req.method==='POST'&&req.headers['content-type']==='application/json'&&!req.headers['transfer-encoding']);
   check(!busy);busy=true;entered=true;
   const now=Date.now();if(now-windowStart>=60000){windowStart=now;attempts=0;}check(++attempts<=60);
   const len=Number(req.headers['content-length']);check(Number.isSafeInteger(len)&&len>=2&&len<=32768);
   let n=0;const chunks=[];for await(const b of req){n+=b.length;check(n<=len);chunks.push(b);}check(n===len);
   const body=JSON.parse(Buffer.concat(chunks).toString('utf8')),peer=sha(cert.raw);
   let result;
   switch(req.url){
    case '/native-session/begin':
     if(Object.hasOwn(body,'enrollmentReceipts')){exact(body,['enrollmentReceipts']);result=state.begin(peer,body.enrollmentReceipts);}
     else{exact(body,[]);result=state.begin(peer);}
     break;
    case '/native-session/open':exact(body,['nonce','receipts']);result=state.open(peer,body);break;
    case '/native-session/whoami':exact(body,['sessionId']);result=state.whoami(peer,body.sessionId);break;
    case '/native-session/lock':exact(body,['sessionId']);result=state.lock(peer,body.sessionId);break;
    case '/native-session/cancel':exact(body,['nonce']);result=state.cancel(peer,body.nonce);break;
    default:throw Error('Unknown operation');
   }
   reply(200,result);
  }catch{reply(403,{error:'native session refused'});}
  finally{if(entered)busy=false;}
 });
 server.requestTimeout=5000;server.headersTimeout=3000;server.keepAliveTimeout=1000;server.maxRequestsPerSocket=1;server.maxConnections=8;
 server.setTimeout(6000,s=>s.destroy());
 await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(port,'127.0.0.1',resolve);});
 return Object.freeze({port:server.address().port,close:()=>new Promise((resolve,reject)=>{state.close();server.close(e=>e?reject(e):resolve());server.closeAllConnections();})});
}
