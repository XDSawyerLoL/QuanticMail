// Explicit loopback-native relay entry point, reusing the existing relay/runtime.
import {open,constants} from 'node:fs/promises';
import {isAbsolute} from 'node:path';
import {createAttestedPeerSource} from '../desktop/native-attested-peer.mjs';
import {startRelayServer} from '../standalone-relay/server.ts';
async function privateConfig(path){
 if(!isAbsolute(path)||typeof process.getuid!=='function')throw Error('absolute POSIX config required');
 const f=await open(path,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
 try{const st=await f.stat();if(!st.isFile()||st.uid!==process.getuid()||(st.mode&0o077)||st.size>32768)throw Error('private config required');
 const b=Buffer.alloc(32769);let n=0;while(n<b.length){const r=await f.read(b,n,b.length-n,null);if(!r.bytesRead)break;n+=r.bytesRead;}if(n>32768)throw Error('config too large');
 return JSON.parse(b.subarray(0,n));}finally{await f.close();}
}
try{
 if(process.argv.length!==4||process.argv[2]!=='--local-native-relay')throw Error('explicit local native relay only');
 const c=await privateConfig(process.argv[3]);
 if(!isAbsolute(c.dataDir)||!Number.isInteger(c.port)||c.port<1||c.port>65535)throw Error('invalid relay config');
 const source=await createAttestedPeerSource(c.authority);
 const relay=await startRelayServer({host:'127.0.0.1',port:c.port,dataDir:c.dataDir,nativePeerSource:source});
 process.stdout.write(JSON.stringify({url:relay.url,mode:'local-native-relay'})+'\n');
 for(const signal of ['SIGINT','SIGTERM'])process.once(signal,()=>{void relay.close().catch(()=>{process.exitCode=1;});});
}catch{process.stderr.write('Démarrage du relais natif refusé.\n');process.exitCode=1;}
