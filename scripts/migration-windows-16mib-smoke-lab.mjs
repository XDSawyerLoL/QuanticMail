// Windows-only SYNTHETIC full-capacity experiment. No real user
// archives or account keys. No renderer, network, migration or deletion.
// Simulate interruption after three candidate chunks, then start a SECOND
// process with separately retained key material through stdin to resume,
// independently read all protected NTFS chunks, and verify exact records.
import {createHash,randomBytes} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {readFileSync} from 'node:fs';
import {win32} from 'node:path';
import {fileURLToPath} from 'node:url';
import {stageChunkedMigrationSnapshot} from '../lib/quantic/migration-chunk-stage-lab.mjs';
import {openChunkedMigrationSnapshot,migrationChunkFileName,MIGRATION_CHUNK_LAB_LIMITS} from '../lib/quantic/migration-chunked-lab.mjs';
import {reconcileHistoricalCollections} from '../lib/quantic/migration-reconcile.mjs';
import {appendMigrationAuditLabRecord,migrationAuditName} from '../lib/quantic/migration-audit-journal-lab.mjs';
const check=ok=>{if(!ok)throw Error('Windows full-capacity restoration rehearsal refused');};
const hexd=/^[a-f0-9]{64}$/,txRE=/^[a-f0-9]{32}$/;
const paths=process.argv.slice(2);
let secret;
let stage='validate-input';
function fixture(){
 const value={messages:[{id:'synthetic-full-capacity-mail',body:''}],
  contacts:[{handle:'synthetic-contact',address:'synthetic@example.invalid'}],
  prekeys:[{preKeyId:'synthetic-expired-prekey',state:'claimed',privateKey:{d:'synthetic-only'}}],
  outbox:[{id:'synthetic-outbox',ciphertext:'synthetic-placeholder'}]};
 const size=Buffer.byteLength(JSON.stringify(value));
 value.messages[0].body='X'.repeat(MIGRATION_CHUNK_LAB_LIMITS.maxPlainBytes-size-1);
 check(Buffer.byteLength(JSON.stringify(value))===MIGRATION_CHUNK_LAB_LIMITS.maxPlainBytes-1);
 return value;
}
function connect(binary,dir){
 const native=(op,name,input)=>execFileSync(binary,[op,dir,...(name?[name]:[])],{
  input,timeout:15000,maxBuffer:140000,windowsHide:true,stdio:['pipe','pipe','ignore']
 });
 return {
  native,
  async read(name){return native('--windows-migration-read-lab',name);},
  async probe(name){const v=native('--windows-migration-probe-lab',name).toString('ascii');check(v==='present'||v==='absent');return v;},
  async write(name,buffer){check(native('--windows-migration-write-lab',name,buffer).length===0);}
 };
}
async function receive(){
 let data='';
 for await(const chunk of process.stdin){data+=chunk.toString();check(data.length<=4096);}
 const q=JSON.parse(data);
 check(q?.labOnly===true&&hexd.test(q.key)&&hexd.test(q.rootPin)&&txRE.test(q.transactionId));
 return q;
}
try{
 const [binary,pin,dir,mode]=paths;
 check(process.platform==='win32'&&paths.length===4&&win32.isAbsolute(binary)&&win32.isAbsolute(dir)
  &&hexd.test(pin)&&(mode==='--synthetic-only'||mode==='--resume'));
 check(createHash('sha256').update(readFileSync(binary)).digest('hex')===pin);
 const storage=connect(binary,dir);
 const history=fixture();
 let info;
 if(mode==='--synthetic-only'){
  stage='create-new-lab';storage.native('--windows-migration-init-lab');
  secret=randomBytes(32);
  info={rootPin:randomBytes(32).toString('hex'),transactionId:randomBytes(16).toString('hex')};
  stage='prepare-full-source';
  const original=await stageChunkedMigrationSnapshot(history,secret,{...info,role:'s'},storage);
  check(original.complete&&original.byteLength===MIGRATION_CHUNK_LAB_LIMITS.maxPlainBytes-1);
  stage='simulate-interruption';
  const interrupted=await stageChunkedMigrationSnapshot(history,secret,{...info,role:'c'},storage,{maxNewChunks:3});
  check(!interrupted.complete&&interrupted.staged===3);
  stage='append-audit-transaction-intent';
  const txFacts={
   sourceManifestSha256:createHash('sha256').update(await storage.read('m-'+info.transactionId+'-s-manifest.enc')).digest('hex'),
   candidateManifestSha256:createHash('sha256').update(await storage.read('m-'+info.transactionId+'-c-manifest.enc')).digest('hex')
  };
  const journal=await appendMigrationAuditLabRecord(storage,secret,info,{sequence:0,phase:'prepared',facts:txFacts});
  check(journal.created&&journal.liveRestoreAuthorized===false);
  // Secret survives only in the trusted parent process, not on disk.
  // The restart is explicit; no autonomous recovery of lost secrets.
  stage='resume-in-new-process';
  const reply=JSON.parse(execFileSync(process.execPath,[fileURLToPath(import.meta.url),binary,pin,dir,'--resume'],{
   input:JSON.stringify({labOnly:true,key:secret.toString('hex'),...info}),
   windowsHide:true,timeout:240000,maxBuffer:8192,stdio:['pipe','pipe','ignore']
  }).toString('utf8'));
  check(reply.status==='synthetic-16mib-windows-restart-passed'&&reply.resumedPreviouslyWrittenChunks>=3
   &&reply.fullSizeVerified&&reply.localAuditJournalVerified===true
   &&reply.liveRestoreAuthorized===false&&reply.legacyDeletionAuthorized===false);
  process.stdout.write(JSON.stringify({...reply,labDirectory:dir})+'\n');
 }else{
  stage='read-out-of-band-resume-credential';
  const q=await receive();secret=Buffer.from(q.key,'hex');
  info={rootPin:q.rootPin,transactionId:q.transactionId};
  stage='authenticate-prepared-journal';
  const expectedFacts={
   sourceManifestSha256:createHash('sha256').update(await storage.read('m-'+info.transactionId+'-s-manifest.enc')).digest('hex'),
   candidateManifestSha256:createHash('sha256').update(await storage.read('m-'+info.transactionId+'-c-manifest.enc')).digest('hex')
  };
  const prepared=await appendMigrationAuditLabRecord(storage,secret,info,{sequence:0,phase:'prepared',facts:expectedFacts});
  check(prepared.created===false&&prepared.liveRestoreAuthorized===false);
  stage='authenticate-preexisting-source';
  const original=await stageChunkedMigrationSnapshot(history,secret,{...info,role:'s'},storage);
  check(original.complete&&original.reused===original.total);
  stage='resume-only-missing-candidate-blocks';
  const restored=await stageChunkedMigrationSnapshot(history,secret,{...info,role:'c'},storage);
  check(restored.complete&&restored.reused>=3);
  const readAll=role=>{
   const ctx={...info,role};
   const parts=[];
   for(let i=0;i<restored.total;i++)parts.push(storage.native('--windows-migration-read-lab',migrationChunkFileName(info.transactionId,role,i)));
   const manifest=storage.native('--windows-migration-read-lab',migrationChunkFileName(info.transactionId,role,'manifest'));
   return openChunkedMigrationSnapshot({manifest,chunks:parts},secret,ctx);
  };
  stage='independent-ntfs-rollback-readback';
  const source=readAll('s'),candidate=readAll('c');
  const report=reconcileHistoricalCollections(source,candidate);
  check(report.historicalCollectionsMatch&&source.prekeys[0].state==='claimed'
   &&candidate.prekeys[0].state==='claimed');
  stage='append-audit-snapshot-verified';
  const verified=await appendMigrationAuditLabRecord(storage,secret,info,{
   sequence:1,phase:'snapshot-verified',
   facts:{historicalCollectionsMatch:true,outboxPreserved:true,prekeysPreserved:true}
  });
  check(verified.created&&verified.liveRestoreAuthorized===false);
  // No relay audit was made in this Windows fixture; phase 2 cannot be
  // written from guessed or in-memory mailbox observations.
  check(await storage.probe(migrationAuditName(info.transactionId,2))==='absent');
  process.stdout.write(JSON.stringify({
   status:'synthetic-16mib-windows-restart-passed',
   fullSizeVerified:restored.byteLength===MIGRATION_CHUNK_LAB_LIMITS.maxPlainBytes-1,
   resumedPreviouslyWrittenChunks:restored.reused,
   chunkCount:restored.total,
   historicalCollectionsMatch:true,sourceIntact:true,localAuditJournalVerified:true,
   liveRestoreAuthorized:false,legacyDeletionAuthorized:false,
   durableTargetVerified:false,remoteQueueReconciled:false,labOnly:true
  })+'\n');
 }
}catch{
 process.stderr.write('Synthetic 16MiB migration refused at '+stage+'; no existing account changed.\n');
 process.exitCode=1;
}finally{secret?.fill(0);}
