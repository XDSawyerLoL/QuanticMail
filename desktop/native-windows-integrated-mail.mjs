// Explicit Windows PQ synthetic compose -> durable native wire -> relay deposit.
// Never bypass the independent pinned native vault or retransmit automatically.
// A failed/unknown transport outcome must preserve the exact original wire.
import {timingSafeEqual,createCipheriv,createDecipheriv,hkdfSync,randomBytes,randomUUID} from 'node:crypto';
import {win32} from 'node:path';
import {normalizeNativeRecord,nativeRecordDigest} from '../lib/quantic/native-mailbox.mjs';
import {connectNativeVault} from './native-vault-controller.mjs';
import {createNativeMailboxClient} from './native-mailbox-client.mjs';
import {safeMailDisplay} from './native-vault-desktop.mjs';
import {windowsLabPath} from './native-windows-storage.mjs';
import {windowsScatteringScope} from './native-windows-mail-flow.mjs';

const check=x=>{if(!x)throw Error('Windows compose/send laboratory refused');};
async function readPrivateJSON(storage,path){
 const bytes=await storage.read(path);
 try{
  check(Buffer.isBuffer(bytes)&&bytes.length>1&&bytes.length<=32768);
  return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));
 }finally{bytes.fill(0);}
}
function validateDraft(draft,scope){
 check(draft&&typeof draft==='object'&&!Array.isArray(draft)
  &&Object.keys(draft).length===2&&draft.context&&draft.payload);
 const c=draft.context;
 check(c.from===scope.address&&c.fromDeviceId===scope.deviceId);
 check(typeof c.to==='string'&&/^[a-z0-9][a-z0-9._-]{2,31}~[a-f0-9]{32}@quantic$/.test(c.to)
  &&typeof c.toDeviceId==='string'&&/^d-[a-f0-9]{32}$/.test(c.toDeviceId)
  &&c.to!==c.from);
 safeMailDisplay(draft.payload);
 return draft;
}
/** A new durable, individually named native wire is always created before
 * any transport call. Record bytes are read back independently and checked
 * against the signed canonical record. No automatic resend, ACK or migration.
 */
export async function composeAndSendWindowsLab(config,storage,{
 input,output,recover=false,approve,
 connect=connectNativeVault,mailboxFactory=createNativeMailboxClient
}){
 const scope=windowsScatteringScope(config);
 check(typeof approve==='function'&&typeof input==='string'&&typeof output==='string'
  &&/^draft-[a-z0-9-]{1,48}\.json$/.test(windowsLabPath(config.windowsLab.dir,input))
  &&/^wire-[a-z0-9-]{1,48}\.json$/.test(windowsLabPath(config.windowsLab.dir,output))
  &&input!==output&&(recover===true||recover===false));
 const stored=await readPrivateJSON(storage,input);
 const draft=validateDraft(stored?.format==='quantic-local-draft-v1'?await openGraphicalDraft(storage,scope,input,stored):stored,scope);
 // An operator sees the exact recipient and plaintext before a broker request.
 if(!await approve('Chiffrer dans le coffre natif le brouillon pour '+draft.context.to+
  '\n'+safeMailDisplay(draft.payload)))return {status:'cancelled-before-seal'};
 let vault;
 let signed;
 try{
  vault=await connect(config);
  signed=await vault.sealHybrid(draft.context,draft.payload,{recover});
  // Validate exact hybrid envelope and sender binding before storage.
  signed=normalizeNativeRecord(signed);
  check(signed.context.from===scope.address&&signed.context.fromDeviceId===scope.deviceId
   &&signed.context.to===draft.context.to&&signed.context.toDeviceId===draft.context.toDeviceId
   &&signed.context.clientMessageId===draft.context.clientMessageId);
 }finally{vault?.close();}
 const digest=nativeRecordDigest(signed);
 const bytes=Buffer.from(JSON.stringify(signed)+'\n','utf8');
 try{
  check(bytes.length<=32768);
  // The Windows native helper exclusively creates and flushes the wire.
  await storage.writeWire(output,bytes);
 }finally{bytes.fill(0);}
 // Independently re-open the just-written private file and verify exact bytes,
 // not only its metadata, before any network request.
 const reread=await storage.read(output);
 try{
  const parsed=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(reread));
  const record=normalizeNativeRecord(parsed);
  check(nativeRecordDigest(record)===digest
   &&record.context.from===scope.address
   &&record.context.fromDeviceId===scope.deviceId
   &&record.context.to===signed.context.to
   &&record.context.toDeviceId===signed.context.toDeviceId);
  const canonical=Buffer.from(JSON.stringify(signed)+'\n','utf8');
  try{
   check(reread.length===canonical.length&&timingSafeEqual(reread,canonical));
  }finally{canonical.fill(0);}
 }finally{reread.fill(0);}
 // Nothing is sent until both durable write and independent reread succeeded.
 if(!await approve('Enveloppe chiffrée enregistrée et vérifiée. Déposer sur le relais local ?'))
  return {status:'saved-not-sent',digest,wireFile:win32.basename(output),
   liveRestoreAuthorized:false,legacyDeletionAuthorized:false};
 // Do not retry an uncertain send. The operator can later use the existing
 // Send operation with the same wire, which has server-side idempotent digest.
 const client=await mailboxFactory(scope);
 const answer=await client.send(signed);
 check(answer?.digest===digest&&['queued','acknowledged'].includes(answer.status)
  &&typeof answer.id==='string');
 return {status:'deposited',id:answer.id,digest,relayStatus:answer.status,
  wireFile:win32.basename(output),
  liveRestoreAuthorized:false,legacyDeletionAuthorized:false};
}

const draftFormat='quantic-local-draft-v1';
function draftAAD(scope,path){
 return Buffer.from(JSON.stringify([draftFormat,scope.address,scope.deviceId,win32.basename(path)]),'utf8');
}
async function draftKey(storage,scope){
 const root=await storage.read(scope.receiptKeyFile);
 try{check(Buffer.isBuffer(root)&&root.length===32);return Buffer.from(hkdfSync('sha256',root,Buffer.alloc(0),Buffer.from('quantic/windows/local-draft/v1'),32));}
 finally{root.fill(0);}
}
async function encryptGraphicalDraft(storage,scope,path,draft){
 const key=await draftKey(storage,scope),raw=Buffer.from(JSON.stringify(draft),'utf8');
 try{
  check(raw.length<=16384);
  const nonce=randomBytes(12),cipher=createCipheriv('aes-256-gcm',key,nonce);
  cipher.setAAD(draftAAD(scope,path));
  const ciphertext=Buffer.concat([cipher.update(raw),cipher.final(),cipher.getAuthTag()]);
  return {format:draftFormat,nonce:nonce.toString('base64url'),ciphertext:ciphertext.toString('base64url')};
 }finally{key.fill(0);raw.fill(0);}
}
async function openGraphicalDraft(storage,scope,path,record){
 check(record&&Object.keys(record).length===3&&record.format===draftFormat&&typeof record.nonce==='string'&&typeof record.ciphertext==='string');
 const nonce=Buffer.from(record.nonce,'base64url'),sealed=Buffer.from(record.ciphertext,'base64url');
 check(nonce.length===12&&nonce.toString('base64url')===record.nonce&&sealed.length>=17&&sealed.length<=16384+16&&sealed.toString('base64url')===record.ciphertext);
 const key=await draftKey(storage,scope);
 let raw,first;
 try{
  const dec=createDecipheriv('aes-256-gcm',key,nonce);
  dec.setAAD(draftAAD(scope,path));dec.setAuthTag(sealed.subarray(-16));
  first=dec.update(sealed.subarray(0,-16));raw=Buffer.concat([first,dec.final()]);
  return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(raw));
 }finally{key.fill(0);first?.fill(0);raw?.fill(0);}
}
export async function createWindowsGraphicalDraft(config,storage,fields,{newId=randomUUID,now=Date.now()}={}){
 const scope=windowsScatteringScope(config),dir=config.windowsLab.dir;
 check(fields&&Object.keys(fields).length===3&&typeof fields.to==='string'&&typeof fields.subject==='string'&&typeof fields.body==='string');
 const payload={subject:fields.subject,body:fields.body};safeMailDisplay(payload);
 check(Buffer.byteLength(JSON.stringify(payload))<=8192);
 const contacts=await readPrivateJSON(storage,win32.join(dir,'contacts.json'));
 check(Array.isArray(contacts)&&contacts.length<=32);
 const matches=contacts.filter(x=>x.address===fields.to&&Number.isSafeInteger(x.expires)&&x.expires>now);
 check(matches.length===1);
 const clientMessageId=newId();check(/^[a-f0-9-]{36}$/.test(clientMessageId));
 const draft=validateDraft({context:{clientMessageId,from:scope.address,fromDeviceId:scope.deviceId,to:fields.to,toDeviceId:matches[0].deviceId},payload},scope);
 const input=win32.join(dir,'draft-'+clientMessageId+'.json'),output=win32.join(dir,'wire-'+clientMessageId+'.json');
 const sealed=await encryptGraphicalDraft(storage,scope,input,draft);
 const bytes=Buffer.from(JSON.stringify(sealed)+'\n','utf8');
 try{await storage.writeDraft(input,bytes);}finally{bytes.fill(0);}
 const readback=await openGraphicalDraft(storage,scope,input,await readPrivateJSON(storage,input));
 check(JSON.stringify(readback)===JSON.stringify(draft));
 return {input,output};
}
