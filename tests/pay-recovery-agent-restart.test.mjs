import test from 'node:test';
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {mkdtempSync,writeFileSync,readFileSync,chmodSync,rmSync,realpathSync} from 'node:fs';
import {join,resolve} from 'node:path';
import {tmpdir} from 'node:os';
import {fileURLToPath} from 'node:url';
const runner=fileURLToPath(new URL('../scripts/quantic-pay-recovery-agent-lab.mjs',import.meta.url));
test('local recovery agent starts again after process exit and retains no in-memory cursor',{skip:process.platform==='win32',timeout:60000},async t=>{
 const root=realpathSync(mkdtempSync(join(tmpdir(),'pay-local-agent-'))),adapter=join(root,'trusted-adapter.mjs'),journal=join(root,'starts.txt');
 try{
  writeFileSync(adapter,`import {appendFileSync} from 'node:fs';
export function createRecoveryWorkerLab(){
 let attempts=0;
 return {
  start(){appendFileSync(${JSON.stringify(journal)},'start\\n');attempts++;return {status:'caught-up'};},
  stats(){return {attempts,claimed:0,released:0,deferred:0,running:true};},
  last(){return {status:'caught-up'};},
  close(){appendFileSync(${JSON.stringify(journal)},'close\\n');}
 };
}
`,{mode:0o600});chmodSync(adapter,0o600);
  async function cycle(){
   const child=spawn(process.execPath,[runner],{env:{...process.env,QUANTIC_PAY_RECOVERY_MODULE:adapter,QUANTIC_PAY_RECOVERY_HEARTBEAT_MS:'100'},stdio:['ignore','pipe','pipe']});
   const events=[],lines=[];let stderr='';
   child.stderr.setEncoding('utf8');child.stderr.on('data',s=>{stderr+=s});
   child.stdout.setEncoding('utf8');child.stdout.on('data',s=>{
    lines.push(s);const joined=lines.join('');let index;
    while((index=joined.indexOf('\n'))>=0){
     const one=joined.slice(0,index);const record=JSON.parse(one);events.push(record);
     lines.splice(0,lines.length,joined.slice(index+1));
     break;
    }
   });
   try{
    const started=Date.now();
    while(!events.some(e=>e.event==='heartbeat')&&Date.now()-started<15000){
     if(child.exitCode!==null)throw Error('runner stopped before heartbeat: '+stderr);
     await new Promise(resolve=>setTimeout(resolve,40));
    }
    assert.ok(events.some(e=>e.event==='ready'),'service never started: '+stderr);
    assert.ok(events.some(e=>e.event==='heartbeat'),'missing autonomous heartbeat: '+stderr);
    const complete=new Promise((res,rej)=>{
     const timeout=setTimeout(()=>rej(Error('SIGTERM shutdown timed out')),10000);
     child.once('close',(code,signal)=>{clearTimeout(timeout);res({code,signal});});
    });
    child.kill('SIGTERM');const ended=await complete;
    assert.equal(ended.code,0,stderr);
    assert.ok(events.some(e=>e.event==='stopped'));
   }finally{
    if(child.exitCode===null)child.kill('SIGKILL');
   }
  }
  await cycle();await cycle();
  assert.deepEqual(readFileSync(journal,'utf8').trim().split('\n'),['start','close','start','close']);
  t.diagnostic('PAY_RECOVERY_AGENT_RESTART_V1 '+JSON.stringify({sequentialBoots:2,gracefulShutdowns:2,heartbeat:true,simulationOnly:true}));
 }finally{rmSync(root,{recursive:true,force:true});}
});
