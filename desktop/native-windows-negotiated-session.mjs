// Explicit native-only client session, owned by the trusted local UI process.
// One broker owns its journal and the carrier; do not expose through HTTP/IPC.
import {createHash} from 'node:crypto';
import {createSocket} from 'node:dgram';
import {win32} from 'node:path';
import {ipv4Endpoint} from './native-managed-scattering.mjs';
import {startWindowsScatteringRotation} from './native-scattering-rotation.mjs';
import {connectNativeVault} from './native-vault-controller.mjs';
import {windowsScatteringScope,runWindowsScatteringMail} from './native-windows-mail-flow.mjs';
import {composeAndSendWindowsLab} from './native-windows-integrated-mail.mjs';
const check=x=>{if(!x)throw Error('Negotiated Windows mail session refused');};
const exact=(o,k)=>o&&typeof o==='object'&&!Array.isArray(o)&&Object.keys(o).length===k.length&&k.every(x=>Object.hasOwn(o,x));
const hex=(x,n)=>typeof x==='string'&&x.length===n&&/^[a-f0-9]+$/.test(x);
const port=x=>Number.isInteger(x)&&x>=1&&x<=65535;
export function validateHybridMailProfile(config,contacts){
 const scope=windowsScatteringScope(config),p=config.managedHybridScattering;
 check(config.labOnly===true&&scope.credentialMode==='vault-sealed-v1'&&config.managedScattering===undefined);
 check(exact(p,['version','channel','peerAddress','peerDeviceId','bootstrapListen','bootstrapTarget','listen','target','epochs'])&&p.version===1&&hex(p.channel,96)&&!/^0+$/.test(p.channel)&&Number.isInteger(p.epochs)&&p.epochs>=1&&p.epochs<=4);
 check(typeof p.peerAddress==='string'&&/^[a-z0-9][a-z0-9._-]{2,31}~[a-f0-9]{32}@quantic$/.test(p.peerAddress)&&typeof p.peerDeviceId==='string'&&/^d-[a-f0-9]{32}$/.test(p.peerDeviceId)&&p.peerAddress!==scope.address&&p.peerDeviceId!==scope.deviceId);
 check(Array.isArray(contacts)&&contacts.length<=32&&contacts.filter(c=>c.address===p.peerAddress&&c.deviceId===p.peerDeviceId&&Number.isSafeInteger(c.expires)&&c.expires>Date.now()).length===1);
 const endpoints=[p.bootstrapListen,p.bootstrapTarget,p.listen,p.target].map(ipv4Endpoint);
 check(new Set(endpoints).size===4);
 // Use distinct local ports, including the fixed loopback mailbox port.
 const httpPort=Number(new URL(scope.endpoint).port);
 check(port(httpPort)&&Number(p.bootstrapListen.split(':')[1])!==Number(p.listen.split(':')[1])&&![p.bootstrapListen,p.listen].some(x=>Number(x.split(':')[1])===httpPort));
 return Object.freeze({...p,httpPort});
}
async function openBootstrap(listen,target){
 const [lh,lp]=listen.split(':'),[th,tp]=target.split(':');
 const socket=createSocket('udp4');
 try{
  await new Promise((resolve,reject)=>{socket.once('error',reject);socket.bind(Number(lp),lh,resolve);});
  await new Promise((resolve,reject)=>{socket.once('error',reject);socket.connect(Number(tp),th,resolve);});
  return socket;
 }catch(e){try{socket.close();}catch{}throw e;}
}
export async function openWindowsNegotiatedMailSession(config,storage,{pacer,binaryPin,signal,onState=()=>{}},{connect=connectNativeVault,rotate=startWindowsScatteringRotation,bootstrap=openBootstrap,compose=composeAndSendWindowsLab,mail=runWindowsScatteringMail}={}){
 check(storage?.dir===config.windowsLab.dir&&typeof storage.createScatteringEpoch==='function'&&typeof storage.verifyBinary==='function'&&typeof pacer==='string'&&win32.isAbsolute(pacer)&&hex(binaryPin,64)&&!signal?.aborted);
 const raw=await storage.read(win32.join(storage.dir,'contacts.json'));let contacts;
 try{contacts=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(raw));}finally{raw.fill(0);}
 const profile=validateHybridMailProfile(config,contacts);
 let controller,socket,rotation,ready=false,closed=false,busy=false;
 const stop=new AbortController();
 const abort=()=>{closed=true;ready=false;stop.abort();controller?.close();};
 signal?.addEventListener('abort',abort,{once:true});
 async function cleanup(){
  abort();signal?.removeEventListener('abort',abort);
  try{await rotation?.close();}finally{try{socket?.close();}catch{}}
 }
 try{
  check(!signal?.aborted);await storage.verifyBinary();
  // Fresh epoch directories; native CREATE_NEW refuses any previous channel.
  // Derive a non-secret directory label; never clean or overwrite on failure.
  const label=createHash('sha256').update(profile.channel).digest('hex').slice(0,32);
  const epochs=[];
  for(let i=0;i<profile.epochs;i++){
   check(!stop.signal.aborted);
   const dir=await storage.createScatteringEpoch('carrier-'+label+'-'+i);
   check(dir===win32.join(storage.dir,'carrier-'+label+'-'+i));
   epochs.push({binary:pacer,binaryPin,listen:profile.listen,target:profile.target,
    config:{labOnly:true,role:'client',queueDir:win32.join(dir,'queue'),stateDir:win32.join(dir,'state'),recvPort:0,httpPort:profile.httpPort},
    windowsBootstrap:{binary:storage.binary,binarySha256:storage.binarySha256,dir},env:storage.env});
  }
  check(!stop.signal.aborted);
  controller=await connect({...config,guiWindowsApproval:true});
  check(controller.lifecycleSignal&&!controller.lifecycleSignal.aborted&&!stop.signal.aborted);
  socket=await bootstrap(profile.bootstrapListen,profile.bootstrapTarget);
  // The same bootstrap socket is reused by non-overlapping generations.
  for(const e of epochs)e.socket=socket;
  check(!stop.signal.aborted);
  rotation=rotate({controller,address:profile.peerAddress,deviceId:profile.peerDeviceId,channel:profile.channel,role:'initiator',epochs,signal:stop.signal,onState:state=>{
   ready=!closed&&state.status==='ready'&&state.httpPort===profile.httpPort;
   onState({status:state.status,generation:state.generation});
  }});
  const finished=rotation.closed.finally(()=>{abort();signal?.removeEventListener('abort',abort);try{socket.close();}catch{}});
  async function operation(fn,options){
   check(!closed&&ready&&!busy&&!controller.lifecycleSignal.aborted);
   busy=true;
   try{return await fn(config,storage,{...options,sessionController:controller});}
   finally{busy=false;}
  }
  return Object.freeze({
   closed:finished,
   close:async()=>{await cleanup();return finished;},
   compose:options=>operation(compose,options),
   mail:options=>operation(mail,options),
   status:()=>closed?'closed':ready?'ready':'negotiating'
  });
 }catch(e){await cleanup();throw e;}
}
