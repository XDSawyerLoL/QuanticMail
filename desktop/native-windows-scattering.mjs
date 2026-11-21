import {spawn} from 'node:child_process';
import {win32} from 'node:path';
import {createWindowsNativeStorage} from './native-windows-storage.mjs';
export async function reserveWindowsScattering(c,bootstrap){
 if(process.platform!=='win32'||c.queueDir!==win32.join(bootstrap.dir,'queue')||c.stateDir!==win32.join(bootstrap.dir,'state')||!(/^[a-f0-9]{64}$/).test(c.epochHex))throw Error('Windows scattering layout refused');
 const storage=await createWindowsNativeStorage(bootstrap);await storage.verifyBinary();
 const p=spawn(storage.binary,['--windows-scattering-guard-lab',storage.dir],{shell:false,cwd:win32.dirname(storage.binary),env:storage.env,windowsHide:true,stdio:['pipe','pipe','ignore']});
 let resolveClosed;const closed=new Promise(r=>{resolveClosed=r;});let ended=false;
 const finish=()=>{if(!ended){ended=true;resolveClosed();}};
 p.on('error',finish);p.on('close',finish);p.stdin.on('error',()=>{p.kill();finish();});
 try{
  await new Promise((resolve,reject)=>{
   let line='';const timer=setTimeout(()=>{p.kill();reject(Error('guard timeout'));},10000);
   const bad=()=>{clearTimeout(timer);reject(Error('guard refused'));};
   p.once('error',bad);p.once('close',bad);
   p.stdout.on('data',b=>{line+=b.toString();if(line==='READY\n'){clearTimeout(timer);resolve();}else if(line.length>=6){p.kill();bad();}});
   p.stdin.write(c.epochHex);
  });
  if(ended)throw Error('guard exited');
  return {closed,close(){p.stdin.end();}};
 }catch(e){p.kill();throw e;}
}
