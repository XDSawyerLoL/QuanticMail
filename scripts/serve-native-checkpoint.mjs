// Local bounded owner-only authority files, no mail-relay signing key.
import {open,constants} from 'node:fs/promises';
import {isAbsolute} from 'node:path';
import {createPrivateKey} from 'node:crypto';
import {startNativeCheckpointAuthority} from '../standalone-relay/native-checkpoint-server.mjs';
async function read(path,max){
 if(!isAbsolute(path)||typeof process.getuid!=='function')throw Error('absolute POSIX path required');
 const f=await open(path,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
 try{
  const s=await f.stat();
  if(!s.isFile()||s.uid!==process.getuid()||(s.mode&0o077)||s.size>max)throw Error('private bounded file required');
  const b=Buffer.alloc(max+1);let n=0;
  while(n<b.length){const r=await f.read(b,n,b.length-n,null);if(!r.bytesRead)break;n+=r.bytesRead;}
  if(n>max)throw Error('file too large');return b.subarray(0,n);
 }finally{await f.close();}
}
try{
 if(process.argv.length!==4||process.argv[2]!=='--local-authority')throw Error('explicit local authority only');
 const c=JSON.parse(await read(process.argv[3],16384));
 const secret=await read(c.authorityKeyFile,4096);let privateKey;
 try{privateKey=createPrivateKey(secret);}finally{secret.fill(0);}
 const service=await startNativeCheckpointAuthority({privateKey,port:c.port,clientPins:c.clientPins,tls:{ca:await read(c.caFile,32768),cert:await read(c.certFile,32768),key:await read(c.keyFile,32768)},load:async()=>({state:JSON.parse(await read(c.stateFile,16*1024*1024)),policy:JSON.parse(await read(c.policyFile,1024*1024))})});
 process.stdout.write(JSON.stringify({port:service.port,mode:'local-lab'})+'\n');
 for(const signal of ['SIGINT','SIGTERM'])process.once(signal,()=>{void service.close().catch(()=>{process.exitCode=1;});});
}catch{process.stderr.write('Autorité HTTPS refusée.\n');process.exitCode=1;}
