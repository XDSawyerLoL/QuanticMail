// Windows-only experimental GUI operation. No browser or terminal, never
// auto-retries a request whose durable wire/relay state might already exist.
import {spawn} from 'node:child_process';
import {randomUUID} from 'node:crypto';
import {win32} from 'node:path';
import {createWindowsNativeStorage} from './native-windows-storage.mjs';
import {bindWindowsDesktopConfig} from './native-windows-desktop.mjs';
import {saveWindowsDraftFromInput} from './native-windows-draft.mjs';
import {composeAndSendWindowsLab} from './native-windows-integrated-mail.mjs';
import {connectNativeVault} from './native-vault-controller.mjs';
import {runWindowsScatteringMail,windowsScatteringScope} from './native-windows-mail-flow.mjs';
import {openReceipt} from './native-receipt-store.mjs';
import {safeMailDisplay} from './native-vault-desktop.mjs';

const check=v=>{if(!v)throw Error('Windows native GUI operation refused');};
async function readConfig(storage,path){
 const raw=await storage.read(path);
 try{check(Buffer.isBuffer(raw)&&raw.length>1&&raw.length<131072);
  return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(raw));
 }finally{raw.fill(0);}
}
// Operator approvals occur in the independently pinned native binary, never
// through untrusted HTML or an "APPROVE" string read from an invisible console.
export async function approveWindowsGUIPrompt(boot,storage,text,{spawnProcess=spawn}={}){
 check(typeof text==='string'&&text.length>0);
 text=text.replace(/\r\n?|\n/gu,' | ');
 check(Buffer.byteLength(text,'utf8')<=1024);
 check(!/[\u0000-\u0008\u000b-\u001f\u007f-\u009f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/u.test(text));
 await storage.verifyBinary();
 return await new Promise((resolve,reject)=>{
  let done=false,bytes=0,chunks=[];
  const child=spawnProcess(boot.binary,['--windows-gui-approve-lab'],{
   shell:false,windowsHide:true,cwd:win32.dirname(boot.binary),
   env:storage.env,stdio:['pipe','pipe','ignore']});
  const finish=(err,approved=false)=>{
   if(done)return;done=true;clearTimeout(timer);
   if(err)child.kill();
   for(const b of chunks)b.fill(0);
   err?reject(err):resolve(approved);
  };
  const timer=setTimeout(()=>finish(Error('Native approval timed out')),120000);
  child.on('error',()=>finish(Error('Native dialog unavailable')));
  child.stdin.on('error',()=>finish(Error('Native dialog unavailable')));
  child.stdout.on('error',()=>finish(Error('Native dialog unavailable')));
  child.stdout.on('data',b=>{bytes+=b.length;if(bytes>64){finish(Error('Invalid native confirmation'));return;}chunks.push(b);});
  child.on('close',status=>{
   if(status===0){
    const v=Buffer.concat(chunks).toString('utf8');
    finish(null,v==='APPROVED\n'); // tampered or unexpected stdout must not approve.
   }else finish(null,false);
  });
  child.stdin.end(Buffer.from(text,'utf8'));
 });
}
export async function composeSendWindowsGUI(boot,fields,{
 makeStorage=createWindowsNativeStorage,
 saveDraft=saveWindowsDraftFromInput,
 compose=composeAndSendWindowsLab,
 approve=approveWindowsGUIPrompt,
 connect=cfg=>connectNativeVault(cfg,{nativeUI:true})
}={}){
 const storage=await makeStorage(boot);
 const cfg=bindWindowsDesktopConfig(await readConfig(storage,win32.join(boot.dir,'desktop.json')),boot);
 // Always preserve an encrypted draft before signing or attempting transport.
 const draft=await saveDraft(boot,fields,{makeStorage:async()=>storage});
 check(draft?.status==='draft-saved-not-sent'&&/^draft-[a-z0-9-]{1,48}\.json$/.test(draft.file));
 const input=win32.join(boot.dir,draft.file);
 const output=win32.join(boot.dir,draft.file.replace(/^draft-/,'wire-'));
 const result=await compose(cfg,storage,{input,output,recover:false,
  approve:text=>approve(boot,storage,text),connect});
 check(['saved-not-sent','deposited','cancelled-before-seal'].includes(result?.status));
 return Object.freeze({...result,encryptedDraft:draft.file,
  noAutomaticRetry:true,remoteDeliveryVerified:false,liveAccountEnrollmentAuthorized:false,
  legacyDeletionAuthorized:false});
}

// Receiving is explicit; an uncertain ACK must never trigger a new decryption.
// A saved receipt can be opened independently and confirmed after restart.
export async function receiveWindowsGUI(boot,operation,receiptFile,{
 makeStorage=createWindowsNativeStorage,
 run=runWindowsScatteringMail,
 approve=approveWindowsGUIPrompt,
 connect=cfg=>connectNativeVault(cfg,{nativeUI:true}),
 makeId=randomUUID
}={}){
 check(['receive','recover-receive','confirm-receipt'].includes(operation));
 const storage=await makeStorage(boot);
 const cfg=bindWindowsDesktopConfig(await readConfig(storage,win32.join(boot.dir,'desktop.json')),boot);
 const scope=windowsScatteringScope(cfg);
 const name=operation==='confirm-receipt'?receiptFile:'receipt-'+makeId().replaceAll('-','')+'.json';
 check(typeof name==='string'&&/^receipt-[a-z0-9-]{1,48}\.json$/.test(name));
 check(operation==='confirm-receipt'||receiptFile===undefined);
 const path=win32.join(boot.dir,name);
 async function authenticatedReceipt(){
  const key=await storage.read(scope.receiptKeyFile);
  try{return openReceipt(key,scope,await readConfig(storage,path));}
  finally{key.fill(0);}
 }
 let result;
 try{
  result=await run(cfg,storage,{operation,path,approve:text=>approve(boot,storage,text),connect});
 }catch(error){
  // A failed network acknowledgement may follow a durable write. Report
  // only a receipt which can be independently authenticated from disk.
  if(operation==='confirm-receipt')throw error;
  let receipt;
  try{receipt=await authenticatedReceipt();}catch{throw error;}
  return Object.freeze({status:'receipt-saved-ack-unknown',receiptFile:name,display:safeMailDisplay(receipt.payload),
   noAutomaticRetry:true,liveAccountEnrollmentAuthorized:false});
 }
 check(['acknowledged','empty','cancelled'].includes(result?.status));
 if(result.status!=='acknowledged')return Object.freeze({status:result.status,noAutomaticRetry:true,liveAccountEnrollmentAuthorized:false});
 const receipt=await authenticatedReceipt();
 check(receipt.id===result.id&&receipt.digest===result.digest);
 return Object.freeze({status:'acknowledged',receiptFile:name,display:safeMailDisplay(receipt.payload),
  noAutomaticRetry:true,liveAccountEnrollmentAuthorized:false});
}
