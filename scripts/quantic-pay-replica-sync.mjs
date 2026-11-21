// One explicit bounded sync pass, only preconfigured Scattering loopback links.
// Private config is supplied by operator; no endpoint discovery or public access.
import {lstatSync,realpathSync,openSync,readFileSync,fstatSync,closeSync,constants} from 'node:fs';
import {isAbsolute} from 'node:path';
import {createPayReplicaCarrier} from '../lib/quantic/pay-replica-carrier.mjs';
import {synchronizePayReplica} from '../lib/quantic/pay-replica-sync.mjs';
const check=v=>{if(!v)throw Error('Replica sync refused');};
const exact=(o,k)=>o&&typeof o==='object'&&!Array.isArray(o)&&Object.keys(o).length===k.length&&k.every(x=>Object.hasOwn(o,x));
async function main(){
 check(process.platform==='linux'&&process.argv.length===3);
 const path=process.argv[2];check(isAbsolute(path)&&realpathSync(path)===path);
 const s=lstatSync(path);check(s.isFile()&&s.uid===process.getuid()&&s.nlink===1&&(s.mode&0o077)===0&&s.size>0&&s.size<=16384);
 const fd=openSync(path,constants.O_RDONLY|constants.O_NOFOLLOW);let c,raw;
 try{const a=fstatSync(fd);check(a.ino===s.ino&&a.dev===s.dev&&a.size===s.size);raw=readFileSync(fd);check(raw.length===s.size);c=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(raw));}finally{raw?.fill(0);closeSync(fd);}
 check(exact(c,['simulationOnly','network','target','peers','maxSteps'])&&c.simulationOnly===true&&Array.isArray(c.peers)&&c.peers.length>=1&&c.peers.length<=3);
 const ports=new Set(),tokens=new Set();
 function endpoint(e){
  check(exact(e,['authorityPin','loopbackPort','token'])&&!ports.has(e.loopbackPort)&&!tokens.has(e.token));ports.add(e.loopbackPort);tokens.add(e.token);
  return {authorityPin:e.authorityPin,client:createPayReplicaCarrier({...e,network:c.network})};
 }
 const target=endpoint(c.target),result=await synchronizePayReplica({network:c.network,targetPin:target.authorityPin,target:target.client,peers:c.peers.map(endpoint),maxSteps:c.maxSteps});
 console.log(JSON.stringify(result));
 if(result.state!=='caught-up-to-observed-peers')process.exitCode=2;
}
main().catch(()=>{console.error('Replica synchronization refused');process.exitCode=1;});
