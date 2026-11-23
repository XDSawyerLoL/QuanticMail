// Native-only one-shot GUI mail transaction. Protocol uses a private
// inherited stdin/stdout pipe; never pass message text or passwords in argv.
// GUI consent is obtained before launch, then again after durable sealing.
import {randomUUID} from 'node:crypto';
import {win32} from 'node:path';
import {createInterface} from 'node:readline';
import {createWindowsNativeStorage} from '../desktop/native-windows-storage.mjs';
import {bindWindowsDesktopConfig} from '../desktop/native-windows-desktop.mjs';
import {saveWindowsDraft} from '../desktop/native-windows-draft.mjs';
import {composeAndSendWindowsLab} from '../desktop/native-windows-integrated-mail.mjs';
import {connectNativeVault} from '../desktop/native-vault-controller.mjs';

const reject=()=>{throw Error('Native GUI transaction refused');};
const args=process.argv.slice(2);
function reply(obj){process.stdout.write(JSON.stringify(obj)+'\n');}
async function jsonPrivate(storage, path) {
 const bytes=await storage.read(path);
 try{
  if(bytes.length<2||bytes.length>131072)reject();
  return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));
 }finally{bytes.fill(0);}
}
function lineInput() {
 const input=createInterface({input:process.stdin,crlfDelay:Infinity});
 const queue=[];let waiting,ended=false;
 input.on('line',line=>{
  if(line.length>16384){ended=true;input.close();if(waiting){waiting.reject(Error('Input too large'));waiting=null;}return;}
  if(waiting){const w=waiting;waiting=null;w.resolve(line);}
  else if(queue.length<2)queue.push(line);
  else {ended=true;input.close();}
 });
 input.on('close',()=>{ended=true;if(waiting){waiting.reject(Error('Private pipe closed'));waiting=null;}});
 return {async next(){
  if(queue.length)return queue.shift();
  if(ended)reject();
  return new Promise((resolve,reject)=>{waiting={resolve,reject};});
 },close(){input.close();}};
}
let savedDraft=null, savedWire=null, stage=0;
let lines;
try{
 if(process.platform!=='win32'||Number(process.versions.node.split('.')[0])<24||
  args.length!==3||process.stdin.isTTY||process.stdout.isTTY)reject();
 lines=lineInput();
 const incoming=await lines.next();
 if(incoming.length<2||Buffer.byteLength(incoming,'utf8')>8192)reject();
 const fields=JSON.parse(incoming);
 const boot={binary:args[0],binarySha256:args[1],dir:args[2]};
 const storage=await createWindowsNativeStorage(boot);
 const dir=boot.dir;
 const config=bindWindowsDesktopConfig(await jsonPrivate(storage,win32.join(dir,'desktop.json')),boot);
 if(config.pqMode?.contactDirectory!==win32.join(dir,'contacts.json'))reject();
 const contacts=await jsonPrivate(storage,win32.join(dir,'contacts.json'));
 const draft=await saveWindowsDraft(config,contacts,storage,fields);
 savedDraft=win32.join(dir,draft.file);
 savedWire=win32.join(dir,'wire-'+randomUUID().replaceAll('-','')+'.json');
 reply({phase:'draft-saved'});
 const result=await composeAndSendWindowsLab(config,storage,{
  input:savedDraft,output:savedWire,
  connect:cfg=>connectNativeVault({...cfg,guiWindowsApproval:true}),
  approve:async()=>{
   stage++;
   if(stage===1)return true; // Existing explicit GUI consent before starting.
   if(stage!==2)return false;
   reply({phase:'sealed-awaiting-deposit-approval'});
   return (await lines.next())==='SEND';
  }
 });
 if(stage>2)reject();
 if(result.status==='deposited'&&result.relayStatus==='queued'){
  reply({phase:'result',status:'queued-on-local-relay',remoteDeliveryVerified:false});
 }else if(result.status==='deposited'&&result.relayStatus==='acknowledged'){
  reply({phase:'result',status:'acknowledged-by-local-relay',remoteDeliveryVerified:false});
 }else if(result.status==='saved-not-sent'){
  reply({phase:'result',status:'encrypted-saved-not-sent',remoteDeliveryVerified:false});
 }else{
  reply({phase:'result',status:'not-sent',remoteDeliveryVerified:false});
 }
}catch{
 // A failed network response might have deposited the exact signed wire.
 // No automatic retry and no data loss. Do not echo private names in logs.
 reply({phase:'result',status:savedWire&&stage===2?'delivery-unknown':'not-sent-confirmed',
  draftPreserved:Boolean(savedDraft),wireMayExist:Boolean(savedWire),
  remoteDeliveryVerified:false});
 process.exitCode=1;
}finally{lines?.close();}
