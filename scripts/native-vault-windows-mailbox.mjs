import {win32} from 'node:path';
import {createInterface} from 'node:readline/promises';
import {createWindowsNativeStorage} from '../desktop/native-windows-storage.mjs';
import {bindWindowsDesktopConfig} from '../desktop/native-windows-desktop.mjs';
import {runWindowsScatteringMail} from '../desktop/native-windows-mail-flow.mjs';
import {composeAndSendWindowsLab} from '../desktop/native-windows-integrated-mail.mjs';
try{
 const [binary,binarySha256,dir,operation,path,output]=process.argv.slice(2);
 const compose=['seal-and-send','recover-seal-and-send'].includes(operation);
 const retry=operation==='retry-send';
 if(process.platform!=='win32'||Number(process.versions.node.split('.')[0])<24
  ||!process.stdin.isTTY||!process.stderr.isTTY
  ||process.argv.length!==((compose||retry)?8:7))throw Error('local terminal required');
 const boot={binary,binarySha256,dir},storage=await createWindowsNativeStorage(boot);
 const b=await storage.read(win32.join(dir,'desktop.json'));let cfg;
 try{cfg=bindWindowsDesktopConfig(JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(b)),boot);}finally{b.fill(0);}
 const approve=async prompt=>{const rl=createInterface({input:process.stdin,output:process.stderr});try{return (await rl.question(prompt+'\nTaper APPROVE : '))==='APPROVE';}finally{rl.close();}};
 let result;
 if(compose){
  result=await composeAndSendWindowsLab(cfg,storage,{
   input:path,output,recover:operation==='recover-seal-and-send',approve
  });
 }else{
  result=await runWindowsScatteringMail(cfg,storage,{operation,path,expectedDigest:retry?output:undefined,approve});
 }
 if(result.display)process.stdout.write(result.display+'\n');
 process.stdout.write(JSON.stringify({
  status:result.status,id:result.id,digest:result.digest,relayStatus:result.relayStatus,
  ...(result.wireFile?{wireFile:result.wireFile}:{}),
  ...(result.retryRequiresConfirmation?{retryRequiresConfirmation:true}:{})
 })+'\n');
 if(result.status==='deposit-unconfirmed'){
  process.stderr.write('Dépôt non confirmé. Message signé conservé. Reprise explicite après rétablissement du transport.\n');
  process.exitCode=1;
 }
}catch{
 process.stderr.write('Opération Scattering non confirmée. Conserver tout brouillon, enveloppe chiffrée et reçu éventuellement enregistrés ; pas de réessai automatique.\n');
 process.exitCode=1;
}
