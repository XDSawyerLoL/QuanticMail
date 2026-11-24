#!/usr/bin/env node
// Local laboratory service entrypoint; no network/server deployment included.
// Its trusted adapter MUST provision the four independent witnesses and
// destination validators. No private keys are read from CLI args or printed.
// OS service supervision (systemd/Task Scheduler) restarts the process.
import {realpathSync,statSync} from 'node:fs';
import {isAbsolute} from 'node:path';
import {pathToFileURL} from 'node:url';
const fail=message=>{throw Error('Quantic Pay recovery lab: '+message);};
const modulePath=process.env.QUANTIC_PAY_RECOVERY_MODULE;
const heartbeatMs=Number(process.env.QUANTIC_PAY_RECOVERY_HEARTBEAT_MS??10000);
const validInterval=Number.isSafeInteger(heartbeatMs)&&heartbeatMs>=100&&heartbeatMs<=60000;
let worker=null,heartbeat=null,stopping=false;
function output(event,fields={}){
 process.stdout.write(JSON.stringify({component:'quantic-pay-recovery-lab',event,
  timestamp:new Date().toISOString(),...fields})+'\n');
}
function status(){
 if(!worker)return;
 const stats=worker.stats(),last=worker.last();
 output('heartbeat',{status:last?.status??'starting',
  attempts:stats.attempts,claimed:stats.claimed,released:stats.released,
  deferred:stats.deferred,running:stats.running===true});
}
async function stop(signal,exitCode=0){
 if(stopping)return;
 stopping=true;
 if(heartbeat!==null){clearInterval(heartbeat);heartbeat=null;}
 try{if(worker)await worker.close();}catch(e){
  process.stderr.write('Recovery lab shutdown failed\n');exitCode=1;
 }
 output('stopped',{signal});
 process.exitCode=exitCode;
}
process.on('SIGINT',()=>{void stop('SIGINT');});
process.on('SIGTERM',()=>{void stop('SIGTERM');});
process.on('uncaughtException',e=>{
 process.stderr.write('Recovery lab fatal: '+String(e?.message??e)+'\n');
 void stop('fatal',1);
});
process.on('unhandledRejection',e=>{
 process.stderr.write('Recovery lab rejection: '+String(e?.message??e)+'\n');
 void stop('rejection',1);
});
try{
 if(typeof modulePath!=='string'||!isAbsolute(modulePath)||!validInterval)fail('invalid private adapter configuration');
 if(realpathSync(modulePath)!==modulePath)fail('symlinked adapter forbidden');
 const stat=statSync(modulePath);
 if(!stat.isFile()||(process.platform!=='win32'
    &&(stat.uid!==process.getuid()||(stat.mode&0o022)!==0)))
  fail('adapter must be owner-controlled and not group/world writable');
 const mod=await import(pathToFileURL(modulePath).href);
 if(typeof mod.createRecoveryWorkerLab!=='function')fail('trusted adapter must export createRecoveryWorkerLab');
 worker=await mod.createRecoveryWorkerLab();
 if(!worker||typeof worker.start!=='function'||typeof worker.stats!=='function'
   ||typeof worker.last!=='function'||typeof worker.close!=='function')
  fail('adapter did not supply the required worker interface');
 const initial=await worker.start();
 output('ready',{status:initial?.status??'starting',laboratoryOnly:true});
 heartbeat=setInterval(status,heartbeatMs);
 // A deferred tick is expected during outages: the worker retries, while
 // systemd/Task Scheduler restarts the process after actual process exits.
}catch(e){
 process.stderr.write('Recovery lab boot refused: '+String(e?.message??e)+'\n');
 await stop('startup-failure',1);
}
