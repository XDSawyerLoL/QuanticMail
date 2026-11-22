// Lab-only mutual-TLS transport for one independently running Quantic Pay
// witness. Each witness keeps its *own* SQLite fence and hybrid signing keys;
// RPC callers receive public signatures but never the signing key material.
// No public payment API, key vault/TPM, certificate issuance or host deploy.
import https from 'node:https';
import tls from 'node:tls';
import {createHash} from 'node:crypto';

const MAX_REQUEST=1024*1024;
const MAX_RESPONSE=256*1024;
const check=v=>{if(!v)throw Error('Remote witness TLS lab refused');};
const hex=v=>typeof v==='string'&&/^[0-9a-f]{64}$/.test(v);
const exact=(o,keys)=>o&&typeof o==='object'&&!Array.isArray(o)
 &&Object.keys(o).length===keys.length&&keys.every(k=>Object.hasOwn(o,k));
const sha=b=>createHash('sha256').update(b).digest('hex');
const pem=v=>typeof v==='string'||Buffer.isBuffer(v);
const response=(res,status,payload)=>{
 const raw=Buffer.from(JSON.stringify(payload));
 res.writeHead(status,{'content-type':'application/json; charset=utf-8',
  'cache-control':'no-store','x-content-type-options':'nosniff',
  'content-length':String(raw.length)});
 res.end(raw);
};
function validTlsConfig(cfg){
 check(exact(cfg,['key','cert','ca'])&&pem(cfg.key)&&pem(cfg.cert)&&pem(cfg.ca));
 return {key:cfg.key,cert:cfg.cert,ca:cfg.ca};
}
function validateOperation(input){
 check(exact(input,['op','args']));
 switch(input.op){
 case 'status':check(exact(input.args,[]));break;
 case 'attest':check(exact(input.args,['challenge'])&&hex(input.args.challenge));break;
 case 'grantCertified':
  check(exact(input.args,['request','proof']));break;
 case 'complete':
  check(exact(input.args,['request','grants','proof']));break;
 default:check(false);
 }
 return input;
}
export async function startPayWitnessMtlsServerLab({
 witness,tls:identity,allowedClientCertPins,host='127.0.0.1',port=0
}){
 check(witness&&['status','attestState','grantCertified','complete','close'].every(k=>typeof witness[k]==='function'));
 check(typeof host==='string'&&host.length>0&&host.length<=255
   &&Number.isSafeInteger(port)&&port>=0&&port<=65535);
 check(Array.isArray(allowedClientCertPins)&&allowedClientCertPins.length>=1
   &&allowedClientCertPins.length<=16
   &&allowedClientCertPins.every(hex)
   &&new Set(allowedClientCertPins).size===allowedClientCertPins.length);
 const allowed=new Set(allowedClientCertPins);
 const server=https.createServer({
  ...validTlsConfig(identity),minVersion:'TLSv1.3',requestCert:true,
  rejectUnauthorized:true,maxHeaderSize:8192
 },async(req,res)=>{
  try{
   const socket=req.socket,cert=socket.getPeerCertificate(true);
   check(socket.authorized===true&&cert?.raw&&allowed.has(sha(cert.raw)));
   check(req.method==='POST'&&req.url==='/v1/witness'
     &&req.headers['content-type']==='application/json'
     &&(!req.headers['content-length']||Number(req.headers['content-length'])<=MAX_REQUEST));
   let total=0;const chunks=[];
   for await(const piece of req){
    total+=piece.length;check(total>0&&total<=MAX_REQUEST);chunks.push(piece);
   }
   const input=validateOperation(JSON.parse(Buffer.concat(chunks).toString('utf8')));
   let result;
   if(input.op==='status')result=witness.status();
   else if(input.op==='attest')result=witness.attestState(input.args.challenge);
   else if(input.op==='grantCertified')result=witness.grantCertified(input.args.request,input.args.proof);
   else result=witness.complete(input.args.request,input.args.grants,input.args.proof);
   response(res,200,{ok:true,result});
  }catch{
   // Do not disclose internal ledger data, errors, raw certificates or keys.
   if(!res.headersSent&&!res.destroyed)response(res,400,{ok:false,error:'refused'});
  }
 });
 server.requestTimeout=7000;
 server.headersTimeout=8000;
 server.keepAliveTimeout=1000;
 server.maxRequestsPerSocket=32;
 try{
  await new Promise((resolve,reject)=>{
   const fail=e=>{server.off('listening',done);reject(e);};
   const done=()=>{server.off('error',fail);resolve();};
   server.once('error',fail);server.once('listening',done);server.listen(port,host);
  });
 }catch(e){server.close();throw e;}
 const a=server.address();
 check(a&&typeof a==='object'&&typeof a.port==='number');
 return Object.freeze({
  host:a.address,port:a.port,
  close:()=>new Promise((resolve,reject)=>{
   server.close(e=>e?reject(e):resolve());
   server.closeIdleConnections();
  })
 });
}
export function openPayWitnessMtlsClientLab({
 url,credentials,serverCertPin,timeoutMs=5000
}){
 check(typeof url==='string'&&hex(serverCertPin)
   &&Number.isSafeInteger(timeoutMs)&&timeoutMs>=200&&timeoutMs<=30000);
 const endpoint=new URL(url);
 check(endpoint.protocol==='https:'&&!endpoint.username&&!endpoint.password
   &&!endpoint.search&&!endpoint.hash&&endpoint.pathname==='/v1/witness');
 const identity=validTlsConfig(credentials);
 function call(op,args){
  const payload=Buffer.from(JSON.stringify({op,args}));
  check(payload.length<=MAX_REQUEST);
  return new Promise((resolve,reject)=>{
   const request=https.request(endpoint,{
    method:'POST',...identity,agent:false,minVersion:'TLSv1.3',
    rejectUnauthorized:true,timeout:timeoutMs,
    headers:{'content-type':'application/json','content-length':String(payload.length)},
    checkServerIdentity(hostname,cert){
     const validation=tls.checkServerIdentity(hostname,cert);
     if(validation)return validation;
     if(!cert?.raw||sha(cert.raw)!==serverCertPin)
      return Error('Remote witness TLS server certificate pin mismatch');
     return undefined;
    }
   },res=>{
    let bytes=0,parts=[];
    res.on('data',piece=>{
     bytes+=piece.length;
     if(bytes>MAX_RESPONSE){request.destroy(Error('Oversized witness response'));return;}
     parts.push(piece);
    });
    res.on('end',()=>{
     try{
      check(res.statusCode===200&&res.headers['content-type']?.startsWith('application/json'));
      const output=JSON.parse(Buffer.concat(parts).toString('utf8'));
      check(exact(output,['ok','result'])&&output.ok===true);
      resolve(output.result);
     }catch{reject(Error('Remote witness refused response'));}
    });
   });
   request.once('timeout',()=>request.destroy(Error('Remote witness timed out')));
   request.once('error',reject);
   request.end(payload);
  });
 }
 return Object.freeze({
  status:()=>call('status',{}),
  attestState:challenge=>{check(hex(challenge));return call('attest',{challenge});},
  grantCertified:(request,proof)=>call('grantCertified',{request,proof}),
  complete:(request,grants,proof)=>call('complete',{request,grants,proof})
 });
}
