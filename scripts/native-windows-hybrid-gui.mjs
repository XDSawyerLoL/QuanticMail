// Long-lived child of the trusted local WinForms composer. No listening IPC.
import {createHash} from 'node:crypto';
import {readFile} from 'node:fs/promises';
import {win32} from 'node:path';
import {createWindowsNativeStorage} from '../desktop/native-windows-storage.mjs';
import {bindWindowsDesktopConfig} from '../desktop/native-windows-desktop.mjs';
import {openWindowsNegotiatedMailSession} from '../desktop/native-windows-negotiated-session.mjs';
import {handleHybridGuiCommand} from '../desktop/native-windows-hybrid-gui.mjs';
const check=x=>{if(!x)throw Error('Private GUI session refused');};
const pin=/^[a-f0-9]{64}$/;const stop=new AbortController();
let session,waiting,buffer=Buffer.alloc(0);
function shutdown(){if(stop.signal.aborted)return;stop.abort();buffer.fill(0);if(waiting){waiting.reject(Error('Private GUI pipe closed'));waiting=null;}void session?.close();}
process.stdin.on('end',shutdown);process.stdin.on('error',shutdown);
process.stdin.on('data',chunk=>{
 if(stop.signal.aborted)return;
 if(!waiting||buffer.length+chunk.length>16384){shutdown();return;}
 const old=buffer;buffer=Buffer.concat([old,chunk]);old.fill(0);
 const i=buffer.indexOf(10);
 if(i<0)return;
 if(i!==buffer.length-1){shutdown();return;}
 const w=waiting;waiting=null;
 try{const line=new TextDecoder('utf-8',{fatal:true}).decode(buffer.subarray(0,i)).replace(/\r$/,'');buffer.fill(0);buffer=Buffer.alloc(0);w.resolve(line);}
 catch(e){w.reject(e);shutdown();}
});
function next(){check(!stop.signal.aborted&&!waiting);const promise=new Promise((resolve,reject)=>{waiting={resolve,reject};});void promise.catch(()=>{});return promise;}
const publish=x=>{check(!stop.signal.aborted);process.stdout.write(JSON.stringify(x)+'\n');};
async function json(storage,name){const raw=await storage.read(win32.join(storage.dir,name));try{return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(raw));}finally{raw.fill(0);}}
try{
 const [binary,binarySha256,dir,manifestPin]=process.argv.slice(2);
 check(process.platform==='win32'&&process.argv.length===6&&!process.stdin.isTTY&&!process.stdout.isTTY&&pin.test(binarySha256)&&pin.test(manifestPin)&&win32.isAbsolute(dir));
 const root=win32.dirname(win32.dirname(binary)),pacer=win32.join(root,'bin','Scattering-Pacer.exe');
 const manifest=await readFile(win32.join(root,'SHA256SUMS.txt'));
 check(manifest.length<=262144&&createHash('sha256').update(manifest).digest('hex')===manifestPin);
 const rows=manifest.toString('utf8').split(/\r?\n/).filter(x=>x.endsWith(' *./bin/Scattering-Pacer.exe'));
 check(rows.length===1&&pin.test(rows[0].slice(0,64))&&rows[0]===rows[0].slice(0,64)+' *./bin/Scattering-Pacer.exe');
 const storage=await createWindowsNativeStorage({binary,binarySha256,dir});
 const config=bindWindowsDesktopConfig(await json(storage,'desktop.json'),{binary,binarySha256,dir});
 const contacts=await json(storage,'contacts.json');
 let ready;const firstReady=new Promise(r=>{ready=r;});
 session=await openWindowsNegotiatedMailSession(config,storage,{pacer,binaryPin:rows[0].slice(0,64),signal:stop.signal,onState:s=>{if(s.status==='ready')ready(true);}});
 void session.closed.then(()=>ready(false),()=>ready(false));
 check(await firstReady&&session.status()==='ready'&&!stop.signal.aborted);
 void session.closed.then(shutdown,shutdown);
 let command=next();publish({phase:'session-ready'});
 while(!stop.signal.aborted){
  const raw=await command;let result;
  try{result=await handleHybridGuiCommand({command:JSON.parse(raw),config,contacts,storage,session,publish,decision:next});}
  catch{if(!stop.signal.aborted)publish({phase:'result',status:'operation-not-confirmed',remoteDeliveryVerified:false});break;}
  if(stop.signal.aborted)break;
  if(result.status==='delivery-unknown'||result.status==='deposit-unconfirmed'){publish(result);break;}
  command=next();publish(result);
 }
}catch{if(!stop.signal.aborted)publish({phase:'session-refused'});process.exitCode=1;}
finally{shutdown();await session?.close();process.stdin.pause();}
