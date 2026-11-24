// Strictly native-only entry point. The config file is independently pinned.
// No public HTTP, admin routes or automatic enrollment on arbitrary requests.
import {open} from 'node:fs/promises';
import {constants} from 'node:fs';
import {createHash} from 'node:crypto';
import {isAbsolute} from 'node:path';
import {createAttestedPeerSource} from '../desktop/native-attested-peer.mjs';
import {startNativeMailboxOnly} from '../standalone-relay/native-mailbox-only.mjs';
let service;
try{
 const [path,pin,flag]=process.argv.slice(2);
 if(process.platform!=='linux'||process.argv.length!==5||flag!=='--synthetic-only'||!isAbsolute(path)||!/^[a-f0-9]{64}$/.test(pin))throw Error('config refused');
 const f=await open(path,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
 let bytes;
 try{const st=await f.stat();if(!st.isFile()||st.uid!==process.getuid()||st.nlink!==1||(st.mode&0o077)||st.size<1||st.size>262144)throw Error('private config required');bytes=await f.readFile();if(bytes.length!==st.size||createHash('sha256').update(bytes).digest('hex')!==pin)throw Error('pin mismatch');}finally{await f.close();}
 const c=JSON.parse(bytes.toString('utf8'));bytes.fill(0);
 if(c?.format!=='quantic-native-enrolled-mailbox-lab/v1'||c.labOnly!==true)throw Error('invalid config');
 // Never trust the enrollment options clock or a roster supplied in a request.
 const source=await createAttestedPeerSource(c.authority);
 let enrollment;
 if(c.enrollment){
  const {request,votes,credential}=c.enrollment;
  enrollment={request,votes,credential,options:{trusted:c.authority.authorities,rosterPin:c.rosterPin,quorumPin:c.quorumPin,approved:c.enrollment.approved===true}};
 }
 service=await startNativeMailboxOnly({dataDir:c.dataDir,port:c.port,peerSource:source,enrollment});
 // Only a minimal public authority snapshot; never print token hashes or mail.
 process.stdout.write(JSON.stringify({status:'native-mailbox-only-lab-ready',port:service.port,publication:service.publication,authoritySnapshot:await service.exportAuthoritySnapshot()})+'\n');
 let stopping=false;
 for(const signal of ['SIGTERM','SIGINT'])process.once(signal,()=>{if(stopping)return;stopping=true;void service.close().catch(()=>{process.exitCode=1;});});
}catch{if(service)await service.close().catch(()=>{});process.stderr.write('Native enrolled mailbox refused. No public listener created.\n');process.exitCode=1;}
