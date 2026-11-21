// Explicit operator tool: private authority signing key stays outside the relay.
import {open,constants} from 'node:fs/promises';
import {isAbsolute} from 'node:path';
import {createPrivateKey} from 'node:crypto';
import {issueCheckpoint} from '../lib/quantic/native-checkpoint-authority.mjs';
async function read(path,max){
 if(!isAbsolute(path)||typeof process.getuid!=='function')throw Error('local POSIX authority only');
 const f=await open(path,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
 try{
  const st=await f.stat();
  if(!st.isFile()||st.uid!==process.getuid()||(st.mode&0o077)||st.size>max)throw Error('private bounded authority file required');
  const out=Buffer.alloc(max+1);let n=0;
  while(n<out.length){const r=await f.read(out,n,out.length-n,null);if(!r.bytesRead)break;n+=r.bytesRead;}
  if(n>max)throw Error('file too large');return out.subarray(0,n);
 }finally{await f.close();}
}
try{
 if(process.argv.length!==7||process.argv[2]!=='--independent-authority')throw Error('explicit authority invocation required');
 const [statePath,policyPath,requestPath,keyPath]=process.argv.slice(3);
 const state=JSON.parse(await read(statePath,16*1024*1024));
 const policy=JSON.parse(await read(policyPath,1024*1024));
 const request=JSON.parse(await read(requestPath,4096));
 const secret=await read(keyPath,4096);
 let key;try{key=createPrivateKey(secret);}finally{secret.fill(0);}
 const result=issueCheckpoint({state,policy,request,privateKey:key});
 process.stdout.write(JSON.stringify(result)+'\n');
}catch{process.stderr.write('Attestation native refusée.\n');process.exitCode=1;}
