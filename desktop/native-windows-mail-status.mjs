// Trusted Node laboratory adapter: read-only local artefact inventory.
// A file's existence is NOT evidence of signature validation or delivery.
import {spawn} from 'node:child_process';
import {win32} from 'node:path';
import {createWindowsNativeStorage} from './native-windows-storage.mjs';

const ensure=(c)=>{if(!c)throw Error('Etat des essais locaux indisponible');};
export async function listWindowsMailAttempts(boot,{makeStorage=createWindowsNativeStorage,spawnProcess=spawn}={}){
 const storage=await makeStorage(boot);
 ensure(storage?.verifyBinary&&storage.env&&win32.isAbsolute(boot.binary)&&win32.isAbsolute(boot.dir));
 await storage.verifyBinary();
 const output=await new Promise((resolve,reject)=>{
  let finished=false,size=0;
  const chunks=[];
  const proc=spawnProcess(boot.binary,['--windows-client-mail-status-lab',boot.dir],{
   cwd:win32.dirname(boot.binary),env:storage.env,windowsHide:true,
   shell:false,stdio:['ignore','pipe','ignore']});
  const finish=(error,value)=>{
   if(finished)return;finished=true;clearTimeout(timer);
   if(error)proc.kill();
   for(const c of chunks)c.fill(0);
   error?reject(error):resolve(value);
  };
  const timer=setTimeout(()=>finish(Error('Local mail status timeout')),10000);
  proc.on('error',()=>finish(Error('Local mail status unavailable')));
  proc.stdout.on('error',()=>finish(Error('Local mail status unavailable')));
  proc.stdout.on('data',chunk=>{
   size+=chunk.length;
   if(size>8192){finish(Error('Local mail status exceeds limit'));return;}
   chunks.push(chunk);
  });
  proc.on('close',code=>{
   if(code!==0){finish(Error('Local mail status refused'));return;}
   finish(null,Buffer.concat(chunks).toString('utf8'));
  });
 });
 let data;
 try{data=JSON.parse(output);}catch{throw Error('Invalid native local status');}
 ensure(data&&Object.getPrototypeOf(data)===Object.prototype
  &&data.status==='local-files-only-unverified'
  &&data.deliveryVerified===false
  &&Array.isArray(data.items)&&data.items.length<=64);
 const ids=new Set();
 const items=[];
 for(const x of data.items){
  ensure(x&&Object.getPrototypeOf(x)===Object.prototype
   &&Object.keys(x).length===3
   &&typeof x.id==='string'&&/^[a-f0-9]{32}$/.test(x.id)
   &&typeof x.draft==='boolean'&&typeof x.wire==='boolean'
   &&(x.draft||x.wire)&&!ids.has(x.id));
  ids.add(x.id);
  items.push(Object.freeze({id:x.id,draft:x.draft,wire:x.wire}));
 }
 return Object.freeze({status:data.status,deliveryVerified:false,items:Object.freeze(items)});
}
