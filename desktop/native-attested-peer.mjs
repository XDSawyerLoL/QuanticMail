// Trusted desktop process only; no renderer IPC, cookies or redirects.
import {request as httpsRequest} from 'node:https';
import {createHash,randomBytes} from 'node:crypto';
import {readFile} from 'node:fs/promises';
import {isAbsolute} from 'node:path';
import {verifyCheckpointQuorum} from '../lib/quantic/native-checkpoint-authority.mjs';
import {bindNativeContact} from '../lib/quantic/native-identity-bridge.mjs';
const check=(ok)=>{if(!ok)throw Error('Attested peer unavailable');};
const hex=/^[a-f0-9]{64}$/;
const address=/^[a-z0-9][a-z0-9._-]{2,31}~[a-f0-9]{32}@quantic$/;
const device=/^d-[a-f0-9]{32}$/;
export async function createAttestedPeerSource(config){
 check(Array.isArray(config?.authorities)&&config.authorities.length===4);
 for(const path of [config.caFile,config.clientCertFile,config.clientKeyFile])check(typeof path==='string'&&isAbsolute(path));
 const tls={ca:await readFile(config.caFile),cert:await readFile(config.clientCertFile),key:await readFile(config.clientKeyFile),minVersion:'TLSv1.3',rejectUnauthorized:true};
 const authorities=config.authorities.map(a=>{
  const u=new URL(a.url);
  check(u.protocol==='https:'&&u.pathname==='/native-checkpoint'&&!u.username&&!u.password&&!u.search&&!u.hash&&hex.test(a.tlsPin)&&hex.test(a.pin));
  return {...a,url:u};
 });
 check(new Set(authorities.map(a=>a.pin)).size===4&&new Set(authorities.map(a=>a.url.origin)).size===4&&new Set(authorities.map(a=>a.tlsPin)).size===4);
 function fetchOne(a,challenge){
  return new Promise((resolve,reject)=>{
   const raw=Buffer.from(JSON.stringify(challenge));let pinned=false;
   const req=httpsRequest(a.url,{...tls,agent:false,method:'POST',headers:{'Content-Type':'application/json','Content-Length':raw.length,'Connection':'close'}},res=>{
    if(!pinned||res.statusCode!==200||res.headers['transfer-encoding']||!/^\d+$/.test(res.headers['content-length']??'')){res.destroy();reject(Error('invalid authority response'));return;}
    const len=Number(res.headers['content-length']);if(len<1||len>131072){res.destroy();reject(Error('authority response size'));return;}
    let total=0;const chunks=[];
    res.on('data',c=>{total+=c.length;if(total>len){res.destroy(Error('oversized response'));return;}chunks.push(c);});
    res.on('error',reject);res.on('end',()=>{try{check(total===len);resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));}catch(e){reject(e);}});
   });
   const timer=setTimeout(()=>req.destroy(Error('authority deadline')),4000);
   req.on('close',()=>clearTimeout(timer));req.on('error',reject);
   req.on('socket',s=>s.once('secureConnect',()=>{
    const cert=s.getPeerCertificate();
    pinned=Boolean(s.authorized&&cert?.raw&&createHash('sha256').update(cert.raw).digest('hex')===a.tlsPin);
    if(!pinned)req.destroy(Error('authority TLS pin mismatch'));
   }));
   req.end(raw);
  });
 }
 return async (addr,dev)=>{
  check(address.test(addr)&&device.test(dev));
  const challenge={address:addr,deviceId:dev,nonce:randomBytes(32).toString('hex'),expires:Date.now()+15000};
  const answers=(await Promise.allSettled(authorities.map(a=>fetchOne(a,challenge)))).filter(r=>r.status==='fulfilled').map(r=>r.value);
  const checkpoint=verifyCheckpointQuorum(answers.map(a=>a.attestation),authorities,challenge);
  for(const a of answers){try{const contact=bindNativeContact(a.bundle,checkpoint);return {bundle:a.bundle,checkpoint,contact};}catch{/* Other authenticated witnesses may provide the correct bundle. */}}
  throw Error('No matching authority bundle');
 };
}
