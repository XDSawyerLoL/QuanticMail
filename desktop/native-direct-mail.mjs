// Direct private link. No hosted mailbox, registry, browser or upstream HTTP.
// The remote acknowledgement proves storage on the authenticated carrier,
// NOT reading/decryption or a globally current revocation status.
import {createHash,createPublicKey,verify,timingSafeEqual} from 'node:crypto';
import {request} from 'node:http';
import {win32} from 'node:path';
import {normalizeNativeRecord,nativeRecordDigest} from '../lib/quantic/native-mailbox.mjs';
import {nativeSenderTranscript} from '../lib/quantic/native-identity-bridge.mjs';
const check=x=>{if(!x)throw Error('Direct native mail refused');};
const sha=b=>createHash('sha256').update(b).digest('hex');
const hex=/^[a-f0-9]{64}$/;
const addr=/^[a-z0-9][a-z0-9._-]{2,31}~[a-f0-9]{32}@quantic$/;
const dev=/^d-[a-f0-9]{32}$/;
const tokenOK=t=>typeof t==='string'&&/^[A-Za-z0-9._~-]{40,256}$/.test(t);
const exact=(o,ks)=>o&&Object.getPrototypeOf(o)===Object.prototype&&Object.keys(o).length===ks.length&&ks.every(k=>Object.hasOwn(o,k));
const json=b=>JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(b));
const answer=(status,body)=>({status,body:Buffer.from(JSON.stringify(body))});
const same=(a,b)=>timingSafeEqual(Buffer.from(sha(a),'hex'),Buffer.from(sha(b),'hex'));
export function validateDirectTrust(t){
 check(exact(t,['format','labOnly','self','peer','contactPin','token'])&&t.format==='quantic-direct-mail/v1'&&t.labOnly===true&&hex.test(t.contactPin)&&!/^0+$/.test(t.contactPin)&&tokenOK(t.token));
 for(const p of [t.self,t.peer])check(exact(p,['address','deviceId'])&&addr.test(p.address)&&dev.test(p.deviceId));
 check(t.self.address!==t.peer.address&&t.self.deviceId!==t.peer.deviceId);
 return t;
}
function pinnedContact(raw,t,now){
 check(Buffer.isBuffer(raw)&&raw.length<=131072&&sha(raw)===t.contactPin);
 const list=json(raw);
 check(Array.isArray(list)&&list.length===1);
 const c=list[0];
 check(exact(c,['address','deviceId','classicalSigningSpki','mlDsaSigningSpki','classicalEncryptionSpki','mlKemEncryptionSpki','expires']));
 check(c.address===t.peer.address&&c.deviceId===t.peer.deviceId&&Number.isSafeInteger(c.expires)&&c.expires>now&&c.expires<=now+86400000);
 function key(field,size,kind){
  const v=c[field];check(typeof v==='string'&&v.length<=Math.ceil(size/3)*4);
  const b=Buffer.from(v,'base64');check(b.length===size&&b.toString('base64')===v);
  const k=createPublicKey({key:b,type:'spki',format:'der'});
  check(k.asymmetricKeyType===kind&&k.export({type:'spki',format:'der'}).equals(b)&&(kind!=='ec'||k.asymmetricKeyDetails?.namedCurve==='prime256v1'));
  return k;
 }
 const signing=key('classicalSigningSpki',91,'ec'),pq=key('mlDsaSigningSpki',1974,'ml-dsa-65');
 key('classicalEncryptionSpki',91,'ec');key('mlKemEncryptionSpki',1206,'ml-kem-768');
 return {signing,pq};
}
function bound(record,from,to){
 const c=record.context;
 check(c.from===from.address&&c.fromDeviceId===from.deviceId&&c.to===to.address&&c.toDeviceId===to.deviceId);
}
export function incomingWireName(record){
 const c=normalizeNativeRecord(record).context;
 return 'wire-in-'+sha(JSON.stringify(['quantic-direct-mail-id/v1',c.from,c.fromDeviceId,c.clientMessageId])).slice(0,40)+'.json';
}
export async function createDirectRecipient({trust,storage,dir,now=Date.now}){
 validateDirectTrust(trust);
 check(storage?.read&&storage?.writeWire&&win32.isAbsolute(dir));
 // Validate locally pinned contact before starting any listening process.
 async function contact(){const b=await storage.read(win32.join(dir,'contacts.json'));try{return pinnedContact(b,trust,now());}finally{b.fill(0);}}
 await contact();
 let busy=false;
 return async function receive(bytes,token){
  if(busy)return answer(503,{error:'direct operation not confirmed'});
  busy=true;
  try{
   check(tokenOK(token)&&same(token,trust.token)&&Buffer.isBuffer(bytes)&&bytes.length>0&&bytes.length<=32768);
   const record=normalizeNativeRecord(json(bytes));
   bound(record,trust.peer,trust.self);
   const keys=await contact(),raw=nativeSenderTranscript(record.context,record.envelope);
   check(verify('sha256',raw,{key:keys.signing,dsaEncoding:'ieee-p1363'},Buffer.from(record.senderAuth.classicalSignature,'base64url')));
   check(verify(null,raw,keys.pq,Buffer.from(record.senderAuth.pqSignature,'base64url')));
   const digest=nativeRecordDigest(record),path=win32.join(dir,incomingWireName(record));
   const data=Buffer.from(JSON.stringify(record)+'\n');
   let duplicate=false;
   try{
    // Native CREATE_NEW + flush; a previously stored logical ID must match
    // exactly. Never overwrite a different ciphertext or acknowledge a
    // missing/partial write. Recheck trust after the durable readback.
    try{await storage.writeWire(path,data);}catch{duplicate=true;}
    const saved=await storage.read(path);
    try{check(saved.equals(data)&&nativeRecordDigest(json(saved))===digest);}finally{saved.fill(0);}
    await contact();
    return answer(202,{status:'peer-stored',digest,duplicate});
   }finally{data.fill(0);}
  }catch{return answer(403,{error:'direct operation not confirmed'});}
  finally{busy=false;}
 };
}
export function createDirectSender({endpoint,trust}){
 validateDirectTrust(trust);
 const u=new URL(endpoint);
 check(u.protocol==='http:'&&u.hostname==='127.0.0.1'&&u.port&&u.pathname==='/'&&!u.username&&!u.password&&!u.search&&!u.hash);
 return Object.freeze({async send(wire){
  const record=normalizeNativeRecord(wire);bound(record,trust.self,trust.peer);
  const digest=nativeRecordDigest(record),raw=Buffer.from(JSON.stringify(record));
  check(raw.length<=32768);
  try{
   return await new Promise((resolve,reject)=>{
    const q=request(new URL('/api/quantic/direct/v1/send',u),{method:'POST',agent:false,headers:{'Content-Type':'application/json','Content-Length':raw.length,Authorization:'Bearer '+trust.token,Connection:'close'}},res=>{
     if(res.statusCode!==202||res.headers['transfer-encoding']||!/^\d+$/.test(res.headers['content-length']??'')||Number(res.headers['content-length'])>512){res.destroy();reject(Error('Direct deposit not confirmed'));return;}
     const chunks=[];let n=0;
     res.on('data',b=>{n+=b.length;if(n>512){res.destroy(Error('Direct response too large'));return;}chunks.push(b);});
     res.on('error',reject);
     res.on('end',()=>{try{const a=json(Buffer.concat(chunks));check(exact(a,['status','digest','duplicate'])&&a.status==='peer-stored'&&a.digest===digest&&typeof a.duplicate==='boolean');resolve(a);}catch(e){reject(e);}});
    });
    const timer=setTimeout(()=>q.destroy(Error('Direct deposit not confirmed')),20000);
    q.on('error',reject);q.on('close',()=>clearTimeout(timer));q.end(raw);
   });
  }finally{raw.fill(0);}
 }});
}
// Reopen the exact signed wire from the sender's own native storage.
// No new encryption, deletion, or implicit retry after ambiguous delivery.
export async function sendStoredDirectWire({trust,storage,dir,file,endpoint,approve,senderFactory=createDirectSender}){
 validateDirectTrust(trust);
 check(/^wire-[a-z0-9-]{1,48}\.json$/.test(file)&&!file.startsWith('wire-in-')&&typeof approve==='function');
 const raw=await storage.read(win32.join(dir,file));let record;
 try{record=normalizeNativeRecord(json(raw));}finally{raw.fill(0);}
 bound(record,trust.self,trust.peer);
 const contactBytes=await storage.read(win32.join(dir,'contacts.json'));
 try{pinnedContact(contactBytes,trust,Date.now());}finally{contactBytes.fill(0);}
 const digest=nativeRecordDigest(record);
 if(!await approve('Déposer directement chez '+trust.peer.address+' ?\\nEmpreinte : '+digest))return {status:'cancelled'};
 const result=await senderFactory({endpoint,trust}).send(record);
 check(result.status==='peer-stored'&&result.digest===digest);
 return {...result,readVerified:false,noAutomaticRetry:true};
}
