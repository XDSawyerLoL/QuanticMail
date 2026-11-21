import {win32} from 'node:path';
import {createWindowsNativeStorage} from '../desktop/native-windows-storage.mjs';
import {startScatteringMailboxEndpoint} from '../standalone-relay/native-scattering-mailbox.mjs';
try{
 const [binary,binarySha256,dir,profile='mailbox']=process.argv.slice(2);
 if(process.platform!=='win32'||![5,6].includes(process.argv.length)||!['mailbox','pay-lab'].includes(profile))throw Error('explicit Windows lab only');
 const bootstrap={binary,binarySha256,dir},storage=await createWindowsNativeStorage(bootstrap);
 const b=await storage.read(win32.join(dir,'scattering.json'));let config;
 try{config=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(b));}finally{b.fill(0);}
 if(!Number.isInteger(config.recvPort)||config.recvPort<1||!Number.isInteger(config.httpPort)||config.httpPort<1)throw Error('fixed ports required');
 const endpoint=await startScatteringMailboxEndpoint(config,{windowsBootstrap:bootstrap,profile});delete config.secretHex;delete config.epochHex;
 console.log(JSON.stringify({mode:'windows-scattering-'+profile+'-lab',recvPort:endpoint.recvPort,httpPort:endpoint.httpPort}));
 for(const sig of ['SIGINT','SIGTERM'])process.once(sig,endpoint.close);
 await endpoint.closed;
}catch{console.error('Windows Scattering lab refused.');process.exitCode=1;}
