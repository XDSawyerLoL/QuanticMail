import {spawn} from 'node:child_process';
import {connectNativeVault} from '../desktop/native-vault-controller.mjs';
import {win32} from 'node:path';
import {createInterface} from 'node:readline/promises';
import {createWindowsNativeStorage} from '../desktop/native-windows-storage.mjs';
import {bindWindowsDesktopConfig} from '../desktop/native-windows-desktop.mjs';
import {runWindowsScatteringMail} from '../desktop/native-windows-mail-flow.mjs';
import {composeAndSendWindowsLab,createWindowsGraphicalDraft} from '../desktop/native-windows-integrated-mail.mjs';
try{
 const args=process.argv.slice(2);
 const graphical=args.at(-1)==='--gui';
 if(graphical)args.pop();
 const [binary,binarySha256,dir,operation]=args;
 let [, , , ,path,output]=args;
 const newCompose=operation==='compose-gui';
 const compose=newCompose||['seal-and-send','recover-seal-and-send'].includes(operation);
 if(process.platform!=='win32'||Number(process.versions.node.split('.')[0])<24
  ||(!graphical&&(!process.stdin.isTTY||!process.stderr.isTTY))
  ||newCompose&&!graphical||args.length!==(newCompose?4:compose?6:5))throw Error('local terminal required');
 const boot={binary,binarySha256,dir},storage=await createWindowsNativeStorage(boot);
 const b=await storage.read(win32.join(dir,'desktop.json'));let cfg;
 try{cfg=bindWindowsDesktopConfig(JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(b)),boot);}finally{b.fill(0);}
 const connect=cfg=>connectNativeVault(cfg,{interaction:graphical?'gui':'console'});
 const guiApprove=async prompt=>{
  const bytes=Buffer.from(prompt,'utf8');
  if(bytes.length<1||bytes.length>16384)throw Error('confirmation bounds');
  await storage.verifyBinary();
  try{return await new Promise((resolve,reject)=>{
   const child=spawn(binary,['--approve-windows-gui-lab'],{shell:false,windowsHide:true,cwd:win32.dirname(binary),env:storage.env,stdio:['pipe','pipe','ignore']});
   let stdout='',done=false;
   const finish=(error,value)=>{if(done)return;done=true;clearTimeout(timer);if(error){child.kill();reject(error)}else resolve(value)};
   const timer=setTimeout(()=>finish(Error('confirmation timed out')),180000);
   child.on('error',()=>finish(Error('confirmation unavailable')));
   child.stdin.on('error',()=>finish(Error('confirmation unavailable')));
   child.stdout.on('error',()=>finish(Error('confirmation unavailable')));
   child.stdout.on('data',chunk=>{stdout+=chunk.toString('utf8');if(stdout.length>128)finish(Error('confirmation refused'));});
   child.on('close',code=>{try{const r=JSON.parse(stdout);if(code!==0||!['approved','cancelled'].includes(r.status))throw Error();finish(null,r.status==='approved');}catch{finish(Error('confirmation unavailable'));}});
   child.stdin.end(bytes);
  });}finally{bytes.fill(0);}
 };
 const approve=graphical?guiApprove:async prompt=>{const rl=createInterface({input:process.stdin,output:process.stderr});try{return (await rl.question(prompt+'\nTaper APPROVE : '))==='APPROVE';}finally{rl.close();}};
 let result;
 if(compose){
  if(newCompose){
   const chunks=[];let n=0;
   try{
    for await(const chunk of process.stdin){n+=chunk.length;if(n>65536){chunk.fill(0);throw Error('compose input bounds');}chunks.push(chunk);}
    const raw=Buffer.concat(chunks);
    try{
     const fields=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(raw));
     ({input:path,output}=await createWindowsGraphicalDraft(cfg,storage,fields));
    }finally{raw.fill(0);}
   }finally{for(const chunk of chunks)chunk.fill(0);}
  }
  result=await composeAndSendWindowsLab(cfg,storage,{
   input:path,output,recover:operation==='recover-seal-and-send',approve,connect
  });
 }else{
  result=await runWindowsScatteringMail(cfg,storage,{operation,path,approve,connect});
 }
 if(!graphical&&result.display)process.stdout.write(result.display+'\n');
 process.stdout.write(JSON.stringify({
  status:result.status,...(graphical&&result.display?{display:result.display}:{}),id:result.id,digest:result.digest,relayStatus:result.relayStatus,
  ...(result.wireFile?{wireFile:result.wireFile}:{})
 })+'\n');
}catch{
 process.stderr.write('Opération Scattering non confirmée. Conserver tout brouillon, enveloppe chiffrée et reçu éventuellement enregistrés ; pas de réessai automatique.\n');
 process.exitCode=1;
}
