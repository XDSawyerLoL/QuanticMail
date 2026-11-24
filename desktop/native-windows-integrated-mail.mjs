// Explicit Windows PQ synthetic compose -> durable native wire -> relay deposit.
// Never bypass the independent pinned native vault or retransmit automatically.
// A failed/unknown transport outcome must preserve the exact original wire.
import {timingSafeEqual,createHash} from 'node:crypto';
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
 input,output,recover=false,approve,reviewedFields,
 connect=connectNativeVault,mailboxFactory=createNativeMailboxClient
}){
 const scope=windowsScatteringScope(config);
 check(typeof approve==='function'&&typeof input==='string'&&typeof output==='string'
  &&/^draft-[a-z0-9-]{1,48}\.json$/.test(windowsLabPath(config.windowsLab.dir,input))
  &&/^wire-[a-z0-9-]{1,48}\.json$/.test(windowsLabPath(config.windowsLab.dir,output))
  &&input!==output&&(recover===true||recover===false));
 const draft=validateDraft(await readPrivateJSON(storage,input),scope);
 // The graphical composer presents the full text before approval. Bind
 // the exact reviewed fields to the durable draft independently reopened
 // here. Never shorten or substitute the message passed to the vault.
 let prompt='Chiffrer dans le coffre natif le brouillon pour '+draft.context.to+'\n'+safeMailDisplay(draft.payload);
 if(reviewedFields!==undefined){
  check(reviewedFields&&Object.getPrototypeOf(reviewedFields)===Object.prototype
   &&Object.keys(reviewedFields).length===3&&['to','subject','body'].every(k=>Object.hasOwn(reviewedFields,k))
   &&reviewedFields.to===draft.context.to&&reviewedFields.subject===draft.payload.subject&&reviewedFields.body===draft.payload.body);
  const raw=Buffer.from(JSON.stringify([draft.context,draft.payload]),'utf8');
  let digest;try{digest=createHash('sha256').update(raw).digest('hex');}finally{raw.fill(0);}
  const subject=Array.from(safeMailDisplay({subject:draft.payload.subject,body:''}).slice(8).trim().replace(/\s+/gu,' ')).slice(0,80).join('');
  prompt='Autoriser le chiffrement du message relu dans la messagerie ?\nDestinataire : '+draft.context.to+
   '\nObjet (apercu, 80 caracteres maximum) : '+subject+
   '\nTexte : '+Buffer.byteLength(draft.payload.body,'utf8')+' octets.\nEmpreinte du brouillon : '+digest;
  check(Buffer.byteLength(prompt.replace(/\r\n?|\n/gu,' | '),'utf8')<=1024);
 }
 if(!await approve(prompt))return {status:'cancelled-before-seal'};
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
