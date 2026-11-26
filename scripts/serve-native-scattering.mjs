// Never pass the shared secret on a command line or through an external API.
import {open,constants} from 'node:fs/promises';
import {isAbsolute} from 'node:path';
import {startScatteringMailboxEndpoint} from '../standalone-relay/native-scattering-mailbox.mjs';
try{
 if(process.platform!=='linux'||process.argv.length!==4||process.argv[2]!=='--two-host-mailbox-lab'||!isAbsolute(process.argv[3]))throw Error('explicit Linux lab only');
 const f=await open(process.argv[3],constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
 let config,b=Buffer.alloc(16385);
 try{
  const s=await f.stat();if(!s.isFile()||s.uid!==process.getuid()||(s.mode&0o077)||s.nlink!==1||s.size>16384)throw Error('private config required');
  let n=0;while(n<b.length){const r=await f.read(b,n,b.length-n,null);if(!r.bytesRead)break;n+=r.bytesRead;}if(n>16384)throw Error('config too large');
  config=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(b.subarray(0,n)));
 }finally{b.fill(0);await f.close();}
 if(!Number.isInteger(config.recvPort)||config.recvPort<1||!Number.isInteger(config.httpPort)||config.httpPort<1)throw Error('fixed port required');
 const endpoint=await startScatteringMailboxEndpoint(config);delete config.secretHex;delete config.epochHex;
 process.stdout.write(JSON.stringify({mode:'scattering-mailbox-lab',recvPort:endpoint.recvPort,httpPort:endpoint.httpPort})+'\n');
 for(const sig of ['SIGINT','SIGTERM'])process.once(sig,endpoint.close);
 await endpoint.closed;
}catch{process.stderr.write('Scattering mailbox lab refused.\n');process.exitCode=1;}
