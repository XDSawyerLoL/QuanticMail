// Explicit single-operator Linux laboratory service.
// Usage: node scripts/run-native-checkpoint-authority-lab.mjs
//   /ABSOLUTE/PRIVATE/AUTHORITY/DIR CONFIG_SHA256
// Startup prints only public authority identity and loopback port.
import {startPinnedNativeAuthorityLab} from '../standalone-relay/native-checkpoint-operator-lab.mjs';
try{
 const [directory,configPin]=process.argv.slice(2);
 if(process.platform!=='linux'||process.argv.length!==4)throw Error('bad operator arguments');
 const server=await startPinnedNativeAuthorityLab({directory,configPin});
 process.stdout.write(JSON.stringify({
  status:'local-synthetic-authority-ready',authorityId:server.authorityId,
  listen:'127.0.0.1',port:server.port,signerPin:server.signerPin,
  tlsPin:server.tlsPin,labOnly:true
 })+'\n');
 let stopping=false;
 const close=async()=>{
  if(stopping)return;stopping=true;
  try{await server.close();}catch{process.exitCode=1;}
 };
 for(const sig of ['SIGINT','SIGTERM'])process.once(sig,()=>{void close();});
}catch{
 process.stderr.write('Native operator authority REFUSED. Never reuse untrusted key, policy or snapshot files.\n');
 process.exitCode=1;
}
