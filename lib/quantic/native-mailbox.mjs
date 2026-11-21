// Versioned native mailbox extension to the existing durable relay snapshot.
// Bounded laboratory queue. Never stores plaintext, credentials or authority bundles.
import {createHash,randomUUID} from 'node:crypto';
import {nativeSenderTranscript} from './native-identity-bridge.mjs';
const check=(ok)=>{if(!ok)throw Error('native mailbox refused');};
const hash=b=>createHash('sha256').update(b).digest('hex');
const maxRows=256;
let entries=new Map();
function exact(obj,keys){check(obj&&typeof obj==='object'&&!Array.isArray(obj)&&Object.keys(obj).length===keys.length&&keys.every(k=>Object.hasOwn(obj,k)));}
export function normalizeNativeRecord(r){
 exact(r,['format','version','context','envelope','senderAuth']);
 check(r.format==='quantic-native-mail'&&r.version===1);
 const c=r.context,e=r.envelope,a=r.senderAuth;
 exact(c,['clientMessageId','from','fromDeviceId','to','toDeviceId']);
 exact(e,['cryptoSuite','keyMode','classicalEphemeralPublicKey','pqKemCiphertext','iv','ciphertext']);
 exact(e.classicalEphemeralPublicKey,['kty','crv','x','y']);
 exact(a,['classicalSignature','pqSignature']);
 nativeSenderTranscript(c,e);
 for(const [s,n] of [[a.classicalSignature,64],[a.pqSignature,3309]]){
  check(typeof s==='string'&&s.length<=Math.ceil(n/3)*4&&/^[A-Za-z0-9_-]+$/.test(s));
  const b=Buffer.from(s,'base64url');check(b.length===n&&b.toString('base64url')===s);
 }
 return {format:r.format,version:r.version,context:{clientMessageId:c.clientMessageId,from:c.from,fromDeviceId:c.fromDeviceId,to:c.to,toDeviceId:c.toDeviceId},envelope:{cryptoSuite:e.cryptoSuite,keyMode:e.keyMode,classicalEphemeralPublicKey:{kty:e.classicalEphemeralPublicKey.kty,crv:e.classicalEphemeralPublicKey.crv,x:e.classicalEphemeralPublicKey.x,y:e.classicalEphemeralPublicKey.y},pqKemCiphertext:e.pqKemCiphertext,iv:e.iv,ciphertext:e.ciphertext},senderAuth:{classicalSignature:a.classicalSignature,pqSignature:a.pqSignature}};
}
const logical=c=>hash(JSON.stringify(['native-mail-id/v1',c.from,c.fromDeviceId,c.clientMessageId]));
export const nativeRecordDigest=r=>hash(JSON.stringify(normalizeNativeRecord(r)));
const status=(row,duplicate=false)=>({id:row.id,digest:row.digest,status:row.acknowledgedAt===null?'queued':'acknowledged',duplicate});
export function nativeMailboxEntries(){return structuredClone([...entries.values()]);}
export function validateNativeMailbox(rows){
 check(Array.isArray(rows)&&rows.length<=maxRows);
 const next=new Map(),ids=new Set();
 for(const r of rows){
  exact(r,['id','digest','record','queuedAt','acknowledgedAt']);
  const record=normalizeNativeRecord(r.record),key=logical(record.context);
  check(typeof r.id==='string'&&/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(r.id)&&!ids.has(r.id)&&!next.has(key));
  check(r.digest===nativeRecordDigest(record)&&Number.isSafeInteger(r.queuedAt)&&r.queuedAt>0&&(r.acknowledgedAt===null||Number.isSafeInteger(r.acknowledgedAt)&&r.acknowledgedAt>=r.queuedAt));
  ids.add(r.id);next.set(key,{...r,record});
 }
 return [...next.values()];
}
export function restoreNativeMailbox(rows){entries=new Map(validateNativeMailbox(rows).map(r=>[logical(r.record.context),r]));}
export function enqueueNativeRecord(record,now=Date.now()){
 record=normalizeNativeRecord(record);
 const key=logical(record.context),digest=nativeRecordDigest(record),prior=entries.get(key);
 if(prior){check(prior.digest===digest);return status(prior,true);}
 check(entries.size<maxRows&&Number.isSafeInteger(now)&&now>0);
 const row={id:randomUUID(),digest,record,queuedAt:now,acknowledgedAt:null};
 entries.set(key,row);return status(row);
}
export function pullNativeRecord(address,deviceId){
 const row=[...entries.values()].find(r=>r.acknowledgedAt===null&&r.record.context.to===address&&r.record.context.toDeviceId===deviceId);
 return row?structuredClone(row):null;
}
// Acknowledgement is mailbox state, not proof of decryption. Retain ciphertext
// and identity tombstone; no automatic deletion or silent reuse of old IDs.
export function acknowledgeNativeRecord(address,deviceId,id,digest,now=Date.now()){
 const row=[...entries.values()].find(r=>r.id===id);
 check(row&&row.record.context.to===address&&row.record.context.toDeviceId===deviceId&&row.digest===digest);
 if(row.acknowledgedAt!==null)return status(row,true);
 check(Number.isSafeInteger(now)&&now>=row.queuedAt);row.acknowledgedAt=now;return status(row);
}
export function recoverNativeRecord(address,deviceId,id,digest){
 const row=[...entries.values()].find(r=>r.id===id);
 check(row&&row.record.context.to===address&&row.record.context.toDeviceId===deviceId&&row.digest===digest);
 return structuredClone(row);
}
