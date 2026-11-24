// One-shot headless GUI helper. Plaintext is read only over a local private pipe.
import {saveWindowsDraftFromInput} from '../desktop/native-windows-draft.mjs';
import {composeSendWindowsGUI,receiveWindowsGUI} from '../desktop/native-windows-gui-send.mjs';
import {listWindowsMailAttempts} from '../desktop/native-windows-mail-status.mjs';
try{
 const args=process.argv.slice(2);
 if(process.platform!=='win32'||process.versions.node.split('.')[0]!=='24'||!([3,4].includes(args.length))||args.length===4&&!['--list','--send','--status','--receive','--recover-receive','--confirm-receipt'].includes(args[3])||process.stdin.isTTY)throw Error('Not the Windows GUI lab');
 if(args[3]==='--status'){
  process.stdout.write(JSON.stringify(await listWindowsMailAttempts({binary:args[0],binarySha256:args[1],dir:args[2]}))+'\n');
 }else if(['--receive','--recover-receive','--confirm-receipt'].includes(args[3])){
 const chunks=[];let length=0;
 for await(const chunk of process.stdin){length+=chunk.length;if(length>128)throw Error('Input too large');chunks.push(chunk);}
 const b=Buffer.concat(chunks);for(const c of chunks)c.fill(0);
 let name;try{if(args[3]==='--confirm-receipt'){name=new TextDecoder('utf-8',{fatal:true}).decode(b);}else if(b.length!==0){throw Error('Unexpected receipt input');}}finally{b.fill(0);}
 const result=await receiveWindowsGUI({binary:args[0],binarySha256:args[1],dir:args[2]},args[3].slice(2),name);
 process.stdout.write(JSON.stringify(result)+'\n');
 }else if(args[3]==='--list'){
  const {listWindowsDraftRecipients}=await import('../desktop/native-windows-draft.mjs');
  process.stdout.write(JSON.stringify(await listWindowsDraftRecipients({binary:args[0],binarySha256:args[1],dir:args[2]}))+'\n');
 } else {
 const chunks=[];let length=0;
 for await(const chunk of process.stdin){
  length+=chunk.length;if(length>8192)throw Error('Input too large');
  chunks.push(chunk);
 }
 const b=Buffer.concat(chunks);for(const chunk of chunks)chunk.fill(0);
 let fields;try{fields=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(b));}finally{b.fill(0);}
 const boot={binary:args[0],binarySha256:args[1],dir:args[2]};
 const result=args[3]==='--send'?await composeSendWindowsGUI(boot,fields):await saveWindowsDraftFromInput(boot,fields);
 process.stdout.write(JSON.stringify(result)+'\n');
 }
}catch{
 // Never echo draft content or cryptographic configuration into diagnostics.
 process.stderr.write('Operation de messagerie non confirmee. Conservez les fichiers prives; aucun renvoi automatique.\n');
 process.exitCode=1;
}
