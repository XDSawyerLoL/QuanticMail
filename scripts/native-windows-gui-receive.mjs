// One-shot GUI-only receive. Never acknowledges mail before the native
// authenticated open, durable encrypted receipt write and independent readback.
import {win32} from 'node:path';
import {createInterface} from 'node:readline';
import {createWindowsNativeStorage} from '../desktop/native-windows-storage.mjs';
import {bindWindowsDesktopConfig} from '../desktop/native-windows-desktop.mjs';
import {receiveWindowsLabFromGUI} from '../desktop/native-windows-gui-receive.mjs';
import {connectNativeVault} from '../desktop/native-vault-controller.mjs';
const reject=()=>{throw Error('GUI receive unavailable');};
const reply=o=>process.stdout.write(JSON.stringify(o)+'\n');
async function privateJSON(storage,path){
 const b=await storage.read(path);
 try{
  if(!Buffer.isBuffer(b)||b.length<2||b.length>131072)reject();
  return JSON.parse(new TextDecoder('utf8',{fatal:true}).decode(b));
 }finally{b.fill(0);}
}
let input;
try{
 const args=process.argv.slice(2);
 if(process.platform!=='win32'||Number(process.versions.node.split('.')[0])<24||
  args.length!==3||process.stdin.isTTY||process.stdout.isTTY)reject();
 const boot={binary:args[0],binarySha256:args[1],dir:args[2]};
 const storage=await createWindowsNativeStorage(boot);
 const cfg=bindWindowsDesktopConfig(await privateJSON(storage,win32.join(boot.dir,'desktop.json')),boot);
 input=createInterface({input:process.stdin,crlfDelay:Infinity});
 let asked=false;
 const result=await receiveWindowsLabFromGUI(cfg,storage,{
  connect:c=>connectNativeVault({...c,guiWindowsApproval:true}),
  approve:async()=>{
   if(asked)return false;
   asked=true;
   reply({phase:'message-awaiting-approval'});
   const answer=await new Promise((resolve,reject)=>{
    const onLine=x=>{cleanup();resolve(x);};
    const onClose=()=>{cleanup();reject(Error('GUI consent pipe closed'));};
    const cleanup=()=>{input.off('line',onLine);input.off('close',onClose);};
    input.once('line',onLine);input.once('close',onClose);
   });
   return answer==='OPEN';
  }
 });
 if(result.status==='opened-and-acknowledged-on-local-relay'){
  reply({phase:'result',status:'opened-and-acknowledged-on-local-relay',
   display:result.display,remoteDeliveryVerified:false});
 }else reply({phase:'result',status:result.status,remoteDeliveryVerified:false});
}catch{
 // A native encrypted receipt may have been written before a failed ACK.
 // Never consume the same item again automatically or claim delivery.
 reply({phase:'result',status:'receive-not-confirmed',remoteDeliveryVerified:false,
  privateReceiptMayExist:true});
 process.exitCode=1;
}finally{input?.close();}
