// Deliberately SYNTHETIC only: a one-command Windows end-to-end check.
// Never reads or imports the existing Web account, mail store or keys.
// The signed package launcher validates the package and binary pins first.
import {createHash,randomBytes} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {readFileSync} from 'node:fs';
import {win32} from 'node:path';
import {fileURLToPath} from 'node:url';
import {sealMigrationCollections} from '../lib/quantic/migration-durable-lab.mjs';

const refuse=condition=>{if(!condition)throw Error('Synthetic Windows migration smoke refused');};
let encryptionKey;
let stage='validate-command';
try {
 const [binary,binaryPin,dir,mode]=process.argv.slice(2);
 refuse(process.platform==='win32'&&process.argv.length===6&&mode==='--synthetic-only');
 refuse(typeof binary==='string'&&win32.isAbsolute(binary)&&typeof dir==='string'&&win32.isAbsolute(dir));
 refuse(typeof binaryPin==='string'&&/^[a-f0-9]{64}$/.test(binaryPin));
 const digest=createHash('sha256').update(readFileSync(binary)).digest('hex');
 refuse(digest===binaryPin);
 encryptionKey=randomBytes(32);
 const historicalPin=randomBytes(32).toString('hex');
 const history={
  messages:[{id:'test-message-1',direction:'in',body:'Synthetic historical mail - not a real account'}],
  contacts:[{handle:'test-contact-1',address:'synthetic@example.invalid'}],
  prekeys:[{preKeyId:'test-prekey-1',state:'claimed',privateKey:{d:'synthetic-only'}}],
  outbox:[{id:'test-outbox-1',ciphertext:'synthetic-only-queue'}]
 };
 // Native helper creates a new protected directory, refuses reuse and
 // commits each encrypted snapshot as an exclusively created NTFS file.
 const native=(op,name,data)=>execFileSync(binary,[op,dir,...(name?[name]:[])],{
  input:data,timeout:20000,maxBuffer:140000,windowsHide:true,stdio:['pipe','pipe','ignore']
 });
 stage='create-private-directory';
 native('--windows-migration-init-lab');
 stage='write-historical-copy';
 native('--windows-migration-write-lab','source.sealed',sealMigrationCollections(history,encryptionKey,{rootPin:historicalPin,role:'source'}));
 stage='write-candidate-copy';
 native('--windows-migration-write-lab','candidate.sealed',sealMigrationCollections(structuredClone(history),encryptionKey,{rootPin:historicalPin,role:'candidate'}));
 // The independent verifier starts afresh, obtains encrypted source and
 // target via native NTFS reads, and compares every historical collection.
 const verifier=fileURLToPath(new URL('./migration-windows-readback-lab.mjs',import.meta.url));
 const input=JSON.stringify({labOnly:true,binary,binaryPin,dir,key:encryptionKey.toString('hex'),rootPin:historicalPin});
 stage='readback-after-restart';
 const result=JSON.parse(execFileSync(process.execPath,[verifier],{
  input,timeout:20000,maxBuffer:8192,windowsHide:true,stdio:['pipe','pipe','ignore']
 }).toString('utf8'));
 stage='validate-independent-reconciliation';
 refuse(result.restartedProcessVerified===true&&result.encryptedWindowsReadback===true&&result.historicalCollectionsMatch===true);
 refuse(result.liveRestoreAuthorized===false&&result.legacyDeletionAuthorized===false&&result.durableTargetVerified===false);
 for(const group of ['messages','contacts','prekeys','outbox'])refuse(result.collections[group].exact===true&&result.collections[group].originalCount===1);
 stage='report-result';
 process.stdout.write(JSON.stringify({
  status:'synthetic-windows-migration-smoke-passed',
  windowsPrivateStorage:true,separateReadbackProcess:true,exactCollections:4,
  labDirectory:dir,liveRestoreAuthorized:false,legacyDeletionAuthorized:false,labOnly:true
 })+'\n');
} catch {
 process.stderr.write('Synthetic Windows migration smoke FAILED CLOSED at '+stage+'. Existing data untouched; do not reuse partial lab directory.\n');
 process.exitCode=1;
} finally {
 encryptionKey?.fill(0);
}
