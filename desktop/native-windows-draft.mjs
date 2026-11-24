// Local-only Windows Alpha composer. No account creation, network or plaintext command-line flags.
import {randomUUID} from 'node:crypto';
import {win32} from 'node:path';
import {safeMailDisplay} from './native-vault-desktop.mjs';
import {bindWindowsDesktopConfig} from './native-windows-desktop.mjs';
import {windowsScatteringScope} from './native-windows-mail-flow.mjs';
import {createWindowsNativeStorage} from './native-windows-storage.mjs';

const check=(v)=>{if(!v)throw Error('Composition de test indisponible ou non autorisee');};
const address=/^[a-z0-9][a-z0-9._-]{2,31}~[a-f0-9]{32}@quantic$/;
const device=/^d-[a-f0-9]{32}$/;
function exact(o,names){check(o&&Object.getPrototypeOf(o)===Object.prototype&&Object.keys(o).length===names.length&&names.every(n=>Object.hasOwn(o,n)));}
async function privateJSON(storage,path){
 const raw=await storage.read(path);
 try{check(Buffer.isBuffer(raw)&&raw.length>1&&raw.length<=131072);
  return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(raw));
 }finally{raw.fill(0);}
}
export async function saveWindowsDraft(config,contacts,storage,fields,{makeId=randomUUID,now=Date.now}={}){
 const scope=windowsScatteringScope(config);
 exact(fields,['to','subject','body']);
 check(typeof fields.to==='string'&&address.test(fields.to)&&fields.to!==scope.address
  &&typeof fields.subject==='string'&&fields.subject.trim().length>0&&fields.subject.length<=160
  &&typeof fields.body==='string'&&fields.body.trim().length>0);
 const payload={subject:fields.subject,body:fields.body};
 safeMailDisplay(payload); // Plain text and hard size bound, never HTML.
 const peers=Array.isArray(contacts)?contacts.filter(c=>c?.address===fields.to&&device.test(c.deviceId)&&Number.isSafeInteger(c.expires)&&c.expires>now()):[];
 check(peers.length===1&&contacts.length<=32);
 const clientMessageId='qs-'+makeId();
 check(/^qs-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(clientMessageId));
 const name='draft-'+clientMessageId.substring(3).replaceAll('-','')+'.json';
 const path=win32.join(config.windowsLab.dir,name);
 const draft={context:{clientMessageId,from:scope.address,fromDeviceId:scope.deviceId,to:fields.to,toDeviceId:peers[0].deviceId},payload};
 const bytes=Buffer.from(JSON.stringify(draft)+'\n','utf8');
 try{
  check(bytes.length<=8192);
  if(scope.credentialMode==='vault-sealed-v1'){
   check(typeof storage.writeEncryptedDraft==='function');await storage.writeEncryptedDraft(path,bytes);
  }else{check(typeof storage.writeDraft==='function');await storage.writeDraft(path,bytes);}
 }finally{bytes.fill(0);}
 const stored=await privateJSON(storage,path);
 if(scope.credentialMode==='vault-sealed-v1'){
  // The native helper has already opened and compared every plaintext field
  // after the durable write. Node only checks that the ciphertext was saved.
  exact(stored,['format','version','file','iv','ciphertext']);
  check(stored.format==='quantic-local-draft'&&stored.version===1&&stored.file===name&&typeof stored.iv==='string'&&typeof stored.ciphertext==='string');
 }else check(JSON.stringify(stored)===JSON.stringify(draft));
 return Object.freeze({status:'draft-saved-not-sent',file:name,liveAccountEnrollmentAuthorized:false,
   remoteDeliveryVerified:false,legacyDeletionAuthorized:false});
}
export async function listWindowsDraftRecipients({binary,binarySha256,dir},{makeStorage=createWindowsNativeStorage}={}){
 const boot={binary,binarySha256,dir},storage=await makeStorage(boot);
 const cfg=bindWindowsDesktopConfig(await privateJSON(storage,win32.join(dir,'desktop.json')),boot);
 windowsScatteringScope(cfg);
 check(cfg.pqMode.contactDirectory===win32.join(dir,'contacts.json'));
 const contacts=await privateJSON(storage,win32.join(dir,'contacts.json'));
 check(Array.isArray(contacts)&&contacts.length<=32);
 const now=Date.now(),used=new Set(),recipients=[];
 for(const c of contacts){
  check(c&&address.test(c.address)&&device.test(c.deviceId)&&Number.isSafeInteger(c.expires)&&c.expires>now&&c.address!==cfg.pqMode.address&&!used.has(c.address));
  used.add(c.address);recipients.push(c.address);
 }
 return Object.freeze({status:'contacts',recipients});
}
export async function saveWindowsDraftFromInput({binary,binarySha256,dir},fields,{makeStorage=createWindowsNativeStorage}={}){
 const boot={binary,binarySha256,dir},storage=await makeStorage(boot);
 const cfg=bindWindowsDesktopConfig(await privateJSON(storage,win32.join(dir,'desktop.json')),boot);
 check(cfg.pqMode.contactDirectory===win32.join(dir,'contacts.json'));
 const contacts=await privateJSON(storage,win32.join(dir,'contacts.json'));
 return saveWindowsDraft(cfg,contacts,storage,fields);
}
