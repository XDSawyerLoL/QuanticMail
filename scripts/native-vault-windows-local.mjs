// Node 24 terminal alternative while the Electron runtime is gated.
import {win32} from 'node:path';
import {createWindowsNativeStorage,windowsLabPath} from '../desktop/native-windows-storage.mjs';
import {bindWindowsDesktopConfig} from '../desktop/native-windows-desktop.mjs';
import {connectNativeVault} from '../desktop/native-vault-controller.mjs';
import {safeMailDisplay} from '../desktop/native-vault-desktop.mjs';
let controller;
try{
 const [binary,binarySha256,dir,op,input,output]=process.argv.slice(2);
 if(process.platform!=='win32'||Number(process.versions.node.split('.')[0])<24||!process.stderr.isTTY||!['open','recover-open','seal','recover-seal'].includes(op))throw Error('invalid invocation');
 const outgoing=op.endsWith('seal'),bootstrap={binary,binarySha256,dir};
 if(process.argv.length!==(outgoing?8:7))throw Error('invalid invocation');
 const storage=await createWindowsNativeStorage(bootstrap);
 const config=bindWindowsDesktopConfig(JSON.parse((await storage.read(win32.join(dir,'desktop.json'))).toString('utf8')),bootstrap);
 const n=windowsLabPath(dir,input);if(!(outgoing?/^draft-/:/^wire-/).test(n))throw Error('wrong input');
 if(outgoing&&!/^wire-/.test(windowsLabPath(dir,output)))throw Error('wrong output');
 const b=await storage.read(input);let record;
 try{record=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(b));}finally{b.fill(0);}
 controller=await connectNativeVault(config);
 const recover=op.startsWith('recover-');
 if(outgoing){
  const wire=await controller.sealHybrid(record.context,record.payload,{recover});
  await storage.writeWire(output,Buffer.from(JSON.stringify(wire)+'\n'));
  process.stderr.write('Encrypted envelope saved locally; not sent.\n');
 }else{
  const payload=await controller.openHybrid(record,{recover});
  process.stdout.write(safeMailDisplay(payload)+'\n');
 }
}catch{
 process.stderr.write('Windows laboratory operation refused. Preserve original inputs. No automatic fallback or retry.\n');process.exitCode=1;
}finally{controller?.close();}
