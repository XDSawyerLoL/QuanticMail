// Explicit loopback Scattering mailbox mode. Trusted local operator and
// independently configured bridge/relay. Never falls back to a remote URL.
import {win32} from 'node:path';
import {readdir} from 'node:fs/promises';
import {createNativeMailboxClient} from './native-mailbox-client.mjs';
import {normalizeNativeRecord,nativeRecordDigest} from '../lib/quantic/native-mailbox.mjs';
import {sealReceipt,openReceipt} from './native-receipt-store.mjs';
import {safeMailDisplay} from './native-vault-desktop.mjs';
import {windowsLabPath} from './native-windows-storage.mjs';
import {connectNativeVault} from './native-vault-controller.mjs';
const check=x=>{if(!x)throw Error('Windows Scattering mail refused');};
async function readJSON(storage,path){
 const b=await storage.read(path);try{return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(b));}finally{b.fill(0);}
}
export function windowsScatteringScope(config){
 const c=config?.windowsScattering,p=config?.pqMode;
 check(c?.enabled===true&&p?.enabled===true&&c.address===p.address&&c.deviceId===p.deviceId&&c.receiptKeyFile===win32.join(config.windowsLab.dir,'receipt.key'));
 const u=new URL(c.endpoint);check(u.protocol==='http:'&&u.hostname==='127.0.0.1'&&u.port&&u.pathname==='/'&&!u.username&&!u.password&&!u.search&&!u.hash);
 return c;
}
// List only metadata of saved signed messages. This is NOT a pending-only queue:
// a saved envelope may already have been deposited or acknowledged.
export async function listWindowsSignedMail(config,storage,{listNames=readdir}={}){
 const scope=windowsScatteringScope(config),dir=config.windowsLab.dir;
 const entries=await listNames(dir,{withFileTypes:true});
 check(Array.isArray(entries)&&entries.length<=2048);
 const names=entries.filter(e=>e.isFile()&&!e.isSymbolicLink()&&/^wire-[a-z0-9-]{1,48}\.json$/.test(e.name)).map(e=>e.name).sort();
 check(names.length<=64);
 const rows=[];
 for(const name of names){
  const path=win32.join(dir,name);windowsLabPath(dir,path);
  const wire=normalizeNativeRecord(await readJSON(storage,path));
  if(wire.context.from!==scope.address||wire.context.fromDeviceId!==scope.deviceId)continue;
  rows.push({name,digest:nativeRecordDigest(wire),recipient:wire.context.to,reference:wire.context.clientMessageId});
 }
 return rows;
}
export async function runWindowsScatteringMail(config,storage,{operation,path,expectedDigest,approve,connect=connectNativeVault,mailboxFactory=createNativeMailboxClient}){
 const scope=windowsScatteringScope(config),dir=config.windowsLab.dir;
 check(typeof approve==='function'&&['send','retry-send','receive','recover-receive','confirm-receipt'].includes(operation));
 const name=windowsLabPath(dir,path);
 const sending=operation==='send'||operation==='retry-send';
 check((sending?/^wire-/:/^receipt-/).test(name));
 if(sending){
  const wire=normalizeNativeRecord(await readJSON(storage,path));
  check(wire.context.from===scope.address&&wire.context.fromDeviceId===scope.deviceId);
  const digest=nativeRecordDigest(wire);
  if(operation==='retry-send')check(typeof expectedDigest==='string'&&/^[a-f0-9]{64}$/.test(expectedDigest)&&digest===expectedDigest);
  const saved={digest,wireFile:name};
  if(!await approve(operation==='retry-send'?'Reprendre le dépôt non confirmé, sans recréer ni modifier le message ?':'Déposer cette enveloppe chiffrée déjà signée ?'))return {status:'cancelled',...saved};
  // Reopen and verify after approval. Never transmit a different wire, even
  // if the file changes while the operator is deciding.
  const reread=normalizeNativeRecord(await readJSON(storage,path));
  check(nativeRecordDigest(reread)===digest);
  try{
   const client=await mailboxFactory(scope);
   const r=await client.send(reread);
   check(r?.digest===digest&&typeof r.duplicate==='boolean'&&['queued','acknowledged'].includes(r.status)
    &&/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(r.id));
   return {status:'deposited',id:r.id,relayStatus:r.status,duplicate:r.duplicate,...saved};
  }catch{return {status:'deposit-unconfirmed',...saved,retryRequiresConfirmation:true};}
 }
 const client=await mailboxFactory(scope);
 const key=await storage.read(scope.receiptKeyFile);
 let controller;
 try{
  check(key.length===32);
  if(operation==='confirm-receipt'){
   const receipt=openReceipt(key,scope,await readJSON(storage,path));
   if(!await approve('Confirmer le reçu chiffré enregistré ?\n'+safeMailDisplay(receipt.payload)))return {status:'cancelled'};
   const r=await client.recover(receipt.id,receipt.digest);
   check(r.id===receipt.id&&r.digest===receipt.digest);
   await client.ack(receipt.id,receipt.digest);
   return {status:'acknowledged',id:receipt.id,digest:receipt.digest};
  }
  const item=await client.pull();
  if(!item)return {status:'empty'};
  if(!await approve('Ouvrir le message authentifié et conserver un reçu chiffré ?'))return {status:'cancelled'};
  // Check account/id/digest and key before consuming the broker journal right.
  sealReceipt(key,scope,item,{subject:'',body:''});
  controller=await connect(config);
  const p=await controller.openHybrid(item.record,{recover:operation==='recover-receive'});
  const payload={subject:p.subject,body:p.body};const display=safeMailDisplay(payload);
  const sealed=sealReceipt(key,scope,item,payload);
  await storage.writeReceipt(path,Buffer.from(JSON.stringify(sealed)+'\n'));
  const stored=openReceipt(key,scope,await readJSON(storage,path));
  check(stored.id===item.id&&stored.digest===item.digest&&stored.payload.subject===payload.subject&&stored.payload.body===payload.body);
  controller.close();controller=undefined;
  // Only after exclusive write-through AND authenticated reread.
  await client.ack(item.id,item.digest);
  return {status:'acknowledged',id:item.id,digest:item.digest,display};
 }finally{key.fill(0);controller?.close();}
}
