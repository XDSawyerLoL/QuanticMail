// Packaged trusted desktop entry point; no console or session ID in UI.
import {createHash} from 'node:crypto';
import {win32} from 'node:path';
import {validateNativeSessionConfiguration} from '../lib/quantic/native-session-kit.mjs';
import {createWindowsNativeStorage} from '../desktop/native-windows-storage.mjs';
import {createWindowsNativeSessionClientLab} from '../desktop/native-session-client.mjs';
const check=x=>{if(!x)throw Error('Session configuration refused');};
const sha=b=>createHash('sha256').update(b).digest('hex');
const hex=/^[a-f0-9]{64}$/;
const exact=(o,keys)=>check(o&&typeof o==='object'&&!Array.isArray(o)&&Object.keys(o).length===keys.length&&keys.every(k=>Object.hasOwn(o,k)));
const emit=(status,fields={})=>process.stdout.write(JSON.stringify({status,...fields})+'\n');
let client,stopping=false,timer,stopPromise;
function stop(){
 if(stopPromise)return stopPromise;
 stopping=true;clearInterval(timer);
 stopPromise=(async()=>{
  const r=client?await client.lock():null;
  emit('locked',{remoteLockConfirmed:r?.remoteLockConfirmed===true});
  process.stdin.pause();
 })();
 return stopPromise;
}
// Any input, pipe EOF or parent-side pipe error cancels; no command eval.
process.stdin.on('data',()=>{void stop();});
process.stdin.on('end',()=>{void stop();});
process.stdin.on('error',()=>{void stop();});
process.stdin.resume();
try{
 const [binary,binarySha256,dir,configPin]=process.argv.slice(2);
 check(process.argv.length===6&&(configPin==='approved'||hex.test(configPin)));
 const storage=await createWindowsNativeStorage({binary,binarySha256,dir});
 let approval=null;
 if(configPin==='approved'){
  const a=await storage.read(win32.join(dir,'session-approval.json'));
  try{approval=JSON.parse(a.toString('utf8'));check(approval&&Object.keys(approval).length===4&&Object.values(approval).every(v=>typeof v==='string'&&hex.test(v)));}finally{a.fill(0);}
 }
 const raw=await storage.read(win32.join(dir,'session.json'));
 let cfg;try{check(sha(raw)===(approval?approval['session.json']:configPin));cfg=JSON.parse(raw.toString('utf8'));}finally{raw.fill(0);}
 exact(cfg,['format','labOnly','service','authorities','candidate','expected','enrollmentReceipts','clientPin','tlsFiles']);
 check(cfg.format==='quantic-native-session-config-lab/v1'&&cfg.labOnly===true&&hex.test(cfg.clientPin));
 exact(cfg.tlsFiles,['ca','cert','key']);
 const readPem=async n=>{check(typeof n==='string'&&/^peer-[a-z0-9-]{1,48}\.pem$/.test(n));const b=await storage.read(win32.join(dir,n));if(approval&&sha(b)!==approval[n]){b.fill(0);throw Error('Approved TLS file changed');}return b;};
 const tls={ca:await readPem(cfg.tlsFiles.ca),cert:await readPem(cfg.tlsFiles.cert),key:await readPem(cfg.tlsFiles.key)};
 try{
  validateNativeSessionConfiguration(cfg,tls);
  if(stopping)throw Error('Cancelled');
  client=await createWindowsNativeSessionClientLab({binary,binarySha256,dir,service:cfg.service,authorities:cfg.authorities,tls,candidate:cfg.candidate,expected:cfg.expected,enrollmentReceipts:cfg.enrollmentReceipts,clientPin:cfg.clientPin,labOnly:true,onEnrollment:status=>emit(status)});
  if(stopping){await client.lock();throw Error('Cancelled');}
  emit('authenticating');
  const session=await client.login();
  if(stopping||!client.isUnlocked())throw Error('Cancelled');
  const identity=await client.whoami();
  if(stopping||!client.isUnlocked())throw Error('Cancelled');
  emit('authenticated',{address:identity.address,expires:session.expires});
  let busy=false;
  await new Promise(resolve=>{
   timer=setInterval(async()=>{
    if(stopping){clearInterval(timer);resolve();return;}
    if(!client.isUnlocked()){await stop();resolve();return;}
    if(busy)return;busy=true;
    try{await client.whoami();}catch{await stop();resolve();}
    finally{busy=false;}
   },1000);
   // EOF/lock must wake this loop even when stop clears the interval.
   const wake=()=>resolve();
   process.stdin.once('data',wake);process.stdin.once('end',wake);process.stdin.once('error',wake);
  });
 }finally{await stop();tls.key.fill(0);}
}catch{
 if(!stopping)emit('refused');
 await stop();process.exitCode=1;
}
