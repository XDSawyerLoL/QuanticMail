import {win32} from 'node:path';
import {createInterface} from 'node:readline/promises';
import {createWindowsNativeStorage} from '../desktop/native-windows-storage.mjs';
import {bindWindowsDesktopConfig} from '../desktop/native-windows-desktop.mjs';
import {runWindowsScatteringMail} from '../desktop/native-windows-mail-flow.mjs';
try{
 const [binary,binarySha256,dir,operation,path]=process.argv.slice(2);
 if(process.platform!=='win32'||Number(process.versions.node.split('.')[0])<24||!process.stdin.isTTY||!process.stderr.isTTY||process.argv.length!==7)throw Error('local terminal required');
 const boot={binary,binarySha256,dir},storage=await createWindowsNativeStorage(boot);
 const b=await storage.read(win32.join(dir,'desktop.json'));let cfg;
 try{cfg=bindWindowsDesktopConfig(JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(b)),boot);}finally{b.fill(0);}
 const approve=async prompt=>{const rl=createInterface({input:process.stdin,output:process.stderr});try{return (await rl.question(prompt+'\nTaper APPROVE : '))==='APPROVE';}finally{rl.close();}};
 const result=await runWindowsScatteringMail(cfg,storage,{operation,path,approve});
 if(result.display)process.stdout.write(result.display+'\n');
 process.stdout.write(JSON.stringify({status:result.status,id:result.id,digest:result.digest,relayStatus:result.relayStatus})+'\n');
}catch{process.stderr.write('Opération Scattering non confirmée. Conserver les entrées et le reçu éventuel, pas de réessai automatique.\n');process.exitCode=1;}
