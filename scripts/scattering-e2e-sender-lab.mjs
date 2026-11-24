#!/usr/bin/env node
// Lab only: two fixed-rate synthetic senders with separate E2E and hop keys.
import {randomBytes} from 'node:crypto';
import {readFileSync,lstatSync} from 'node:fs';
import {mkdtemp,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,isAbsolute} from 'node:path';
import {spawn} from 'node:child_process';
import {sealNestedLab,E2E_LAB} from '../lib/quantic/scattering-e2e-envelope-lab.mjs';
import {writeSpool} from '../labs/quantic-native/scattering/scattering-cell.mjs';

const check=(x,msg)=>{if(!x)throw Error(msg)};
function readLabKey(p){
 check(isAbsolute(p),'absolute key path required');
 const f=lstatSync(p);
 check(f.isFile()&&f.size===32&&(f.mode&0o077)===0,'invalid lab key');
 return readFileSync(p);
}
async function main(){
 const [binary,target,port,secondsRaw,hopPath,e2ePath,senderRaw]=process.argv.slice(2);
 const seconds=Number(secondsRaw),senderId=Number(senderRaw);
 check(typeof binary==='string'&&isAbsolute(binary)&&['10.252.41.2','10.252.42.2'].includes(target)&&
  (target==='10.252.41.2'?(port==='49001'&&senderId===0):(port==='49002'&&senderId===1))&&
  Number.isInteger(seconds)&&seconds>=5&&seconds<=10,'bounded lab source only');
 const hopKey=readLabKey(hopPath),e2eKey=readLabKey(e2ePath);
 const dir=await mkdtemp(join(tmpdir(),'qs-e2e-source-'));
 try{
  const count=seconds*20+40,cells=[];
  for(let seq=0;seq<count;seq++)
   cells.push(sealNestedLab({hopKey,endToEndKey:e2eKey,senderId,seq,
      data:randomBytes(E2E_LAB.dataLength)}));
  writeSpool(dir,cells);
  const args=['-target',target+':'+port,'-queue-dir',dir,'-period-us','50000',
    '-poll','10ms','-wait-mode','native','-duration',seconds+'s'];
  const report=await new Promise((resolve,reject)=>{
   const child=spawn(binary,args,{shell:false,windowsHide:true,stdio:['ignore','pipe','pipe']});
   let stdout='',stderr='';
   child.stdout.on('data',d=>stdout=(stdout+d.toString()).slice(-4096));
   child.stderr.on('data',d=>stderr=(stderr+d.toString()).slice(-4096));
   child.once('error',reject);
   child.once('close',code=>code===0?resolve(stdout.trim()):reject(Error('pacer failed '+code+' '+stderr.slice(-500))));
  });
  const m=/planned=(\d+) sent=(\d+) missed=(\d+)/.exec(report);
  check(m&&Number(m[2])>=seconds*18&&Number(m[3])<=Number(m[1]),'native pacer missed slots');
  console.log(JSON.stringify({mode:'nested-e2e-synthetic-send',senderId,planned:Number(m[1]),
    sent:Number(m[2]),missed:Number(m[3]),cellBytes:168,innerBytes:92,
    e2eKeyGivenToRelay:false,realAccountsUsed:false}));
 }finally{hopKey.fill(0);e2eKey.fill(0);await rm(dir,{recursive:true,force:true});}
}
main().catch(e=>{console.error('nested source failed: '+e.message);process.exitCode=1;});
