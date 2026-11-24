// Fail-closed lifecycle guard. Native watcher is started before login,
// and a lost watcher cannot be silently replaced by an unlocked session.
import {spawn} from 'node:child_process';
import {win32} from 'node:path';
import {createWindowsNativeStorage} from './native-windows-storage.mjs';
const refused=()=>Error('Windows interactive session unavailable');
export function bindSessionLifetime(client,watch,{deadline=2500}={}){
 let stopped=false,ready=false,buffer='',timer;
 let resolveReady,rejectReady;
 const started=new Promise((res,rej)=>{resolveReady=res;rejectReady=rej;});
 let lockResult;
 function stop(){
  if(stopped)return lockResult;
  stopped=true;clearTimeout(timer);
  rejectReady(refused());
  // lock invalidates the local generation synchronously before I/O.
  try{lockResult=Promise.resolve(client.lock());}catch{lockResult=Promise.reject(refused());}
  lockResult.catch(()=>{});
  try{watch.kill();}catch{}
  return lockResult;
 }
 function arm(){clearTimeout(timer);timer=setTimeout(stop,deadline);}
 watch.on('error',stop);watch.on('exit',stop);watch.on('close',stop);
 watch.stdin.on('error',stop);watch.stdout.on('error',stop);
 watch.stdout.on('data',chunk=>{
  if(stopped)return;
  buffer+=chunk.toString('ascii');
  if(buffer.length>128){stop();return;}
  let i;
  while((i=buffer.indexOf('\n'))>=0&&!stopped){
   const line=buffer.slice(0,i).replace(/\r$/,'');buffer=buffer.slice(i+1);
   if(!ready&&line==='READY'){ready=true;arm();resolveReady();}
   else if(ready&&line==='ALIVE'){arm();}
   else{stop();}
  }
 });
 arm();
 function guard(){if(stopped||!ready)throw refused();}
 return Object.freeze({
  started,
  async login(){await started;guard();const result=await client.login();guard();return result;},
  async whoami(){guard();const result=await client.whoami();guard();return result;},
  async lock(){return await stop();},
  isUnlocked(){return !stopped&&ready&&client.isUnlocked();}
 });
}
export async function watchWindowsSessionLifetime(config,client){
 const storage=await createWindowsNativeStorage(config);
 await storage.verifyBinary();
 const watch=spawn(storage.binary,['--watch-windows-session-lab'],{shell:false,windowsHide:true,cwd:win32.dirname(storage.binary),env:storage.env,stdio:['pipe','pipe','ignore']});
 const guarded=bindSessionLifetime(client,watch);
 await guarded.started;
 return guarded;
}
