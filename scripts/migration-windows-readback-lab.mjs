// Spawned in a NEW Node process by the Windows synthetic test. No real
// identity, no renderer, no network, no registry writes and no deletion.
// A trusted calling process supplies the key, original root pin and binary
// SHA-256 via stdin, not argv or filesystem.
import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {execFileSync} from 'node:child_process';
import {openMigrationCollections} from '../lib/quantic/migration-durable-lab.mjs';
import {reconcileHistoricalCollections} from '../lib/quantic/migration-reconcile.mjs';
const check=ok=>{if(!ok)throw Error('Windows migration readback refused');};
async function readRequest(){
 let raw='';
 for await(const chunk of process.stdin){
  raw+=chunk.toString('utf8');check(raw.length<=4096);
 }
 return JSON.parse(raw);
}
try{
 const q=await readRequest();
 check(process.platform==='win32'&&q.labOnly===true&&typeof q.binary==='string'
  &&typeof q.dir==='string'&&typeof q.binaryPin==='string'&&/^[a-f0-9]{64}$/.test(q.binaryPin)
  &&typeof q.key==='string'&&/^[a-f0-9]{64}$/.test(q.key));
 check(createHash('sha256').update(readFileSync(q.binary)).digest('hex')===q.binaryPin);
 const key=Buffer.from(q.key,'hex');
 const read=(name)=>execFileSync(q.binary,['--windows-migration-read-lab',q.dir,name],{windowsHide:true,timeout:15000,maxBuffer:140000,stdio:['ignore','pipe','ignore']});
 const original=openMigrationCollections(read('source.sealed'),key,{rootPin:q.rootPin,role:'source'});
 const recovered=openMigrationCollections(read('candidate.sealed'),key,{rootPin:q.rootPin,role:'candidate'});
 const report=reconcileHistoricalCollections(original,recovered);
 check(report.historicalCollectionsMatch);
 process.stdout.write(JSON.stringify({restartedProcessVerified:true,encryptedWindowsReadback:true,collections:report.collections,
  historicalCollectionsMatch:true,durableTargetVerified:false,remoteQueueReconciled:false,
  liveRegistrationAuthorized:false,liveRestoreAuthorized:false,legacyDeletionAuthorized:false,labOnly:true})+'\n');
 key.fill(0);
}catch{
 process.stderr.write('Windows isolated recovery readback refused\n');
 process.exitCode=1;
}
