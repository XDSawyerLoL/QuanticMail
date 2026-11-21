// Conventional fixed 3-of-4 external CAS replication, not BFT consensus.
// Independent trusted custody and exclusive guarded replica ownership required.
// No automatic repair, retry, reconfiguration, or tolerance of colluding hosts.
import {X509Certificate,createHash} from 'node:crypto';
import {createPayAnchorClient} from './pay-anchor-client.mjs';
import {config,check,exact,hex,port,privateRead} from './pay-anchor-config.mjs';
import {assertExternalPayCheckpoint} from './pay-external-checkpoint.mjs';
const equal=(a,b)=>{try{return assertExternalPayCheckpoint(a,b);}catch{return false;}};
export function createPayAnchorQuorum({configFile,network,authorityPin}){
 const c=config(configFile);
 check(exact(c,['simulationOnly','network','authorityPin','members'])&&c.simulationOnly===true&&hex(network)&&hex(authorityPin)&&c.network===network&&c.authorityPin===authorityPin&&Array.isArray(c.members)&&c.members.length===4&&new Set(c.members).size===4);
 const ports=new Set(),tokens=new Set(),certs=new Set(),keys=new Set();
 const members=c.members.map(path=>{
  const a=config(path);
  check(exact(a,['simulationOnly','network','authorityPin','port','token','certFile'])&&a.simulationOnly===true&&a.network===network&&a.authorityPin===authorityPin&&port(a.port)&&hex(a.token));
  const cert=new X509Certificate(privateRead(a.certFile,16384));
  const fingerprint=cert.fingerprint256, key=createHash('sha256').update(cert.publicKey.export({format:'der',type:'spki'})).digest('hex');
  check(!ports.has(a.port)&&!tokens.has(a.token)&&!certs.has(fingerprint)&&!keys.has(key));
  ports.add(a.port);tokens.add(a.token);certs.add(fingerprint);keys.add(key);
  const baseline=JSON.stringify(a),client=createPayAnchorClient({configFile:path,network,authorityPin});
  return {client,verifyConfig(){
   // Private operator-owned files must remain unchanged during use.
   check(JSON.stringify(config(path))===baseline&&new X509Certificate(privateRead(a.certFile,16384)).fingerprint256===fingerprint);
  }};
 });
 let halted=false,busy=false;
 function collect(fn){
  const answers=[];
  for(const m of members){
   try{m.verifyConfig();answers.push(fn(m.client));}catch{/* not a vote */}
  }
  return answers;
 }
 function matching(){
  const groups=[];
  for(const a of collect(c=>c.read())){
   const g=groups.find(g=>equal(g.value,a));
   if(g)g.count++;else groups.push({value:a,count:1});
  }
  const winner=groups.find(g=>g.count>=3);
  check(winner);return structuredClone(winner.value);
 }
 function operation(fn){
  check(!halted&&!busy);busy=true;
  try{return fn();}catch(e){halted=true;throw Error('Pay anchor quorum halted; independent reconciliation required',{cause:e});}
  finally{busy=false;}
 }
 return Object.freeze({
  read:()=>operation(matching),
  compareAndSwap(before,after){return operation(()=>{
   assertExternalPayCheckpoint(before,matching());
   assertExternalPayCheckpoint(after,after);
   check(after.network===network&&after.authorityPin===authorityPin);
   const acks=collect(c=>c.compareAndSwap(before,after)).filter(v=>v===true);
   check(acks.length>=3);
   assertExternalPayCheckpoint(after,matching());
   return true;
  });},
  status:()=>Object.freeze({size:4,quorum:3,halted,simulationOnly:true})
 });
}
