import test from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes,createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {readFileSync,writeFileSync,rmSync,existsSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join,isAbsolute} from 'node:path';
import {fileURLToPath} from 'node:url';
import {sealMigrationCollections,openMigrationCollections} from '../lib/quantic/migration-durable-lab.mjs';

const windows=process.platform==='win32'&&!!process.env.QUANTIC_WINDOWS_VAULT_TEST;
test('Windows private NTFS readback survives a new Node process; refusal keeps source recoverable',{skip:!windows},()=>{
 const binary=process.env.QUANTIC_WINDOWS_VAULT_TEST;
 assert.ok(isAbsolute(binary));
 const binaryPin=createHash('sha256').update(readFileSync(binary)).digest('hex');
 const dir=join(tmpdir(),'QuanticMigrationLab-'+randomBytes(8).toString('hex'));
 const rootPin='1'.repeat(64),key=randomBytes(32);
 const source={messages:[{id:'historic-m1',body:'sensitive historical text'}],
  contacts:[{handle:'old-contact',address:'synthetic@example.invalid'}],
  prekeys:[{preKeyId:'historic-p1',state:'claimed',privateKey:{d:'synthetic'}}],
  outbox:[{id:'pending-out',ciphertext:'synthetic encrypted message'}]};
 const command=(op,name,bytes)=>execFileSync(binary,[op,dir,...(name?[name]:[])],{input:bytes,windowsHide:true,timeout:15000,maxBuffer:140000,stdio:['pipe','pipe','ignore']});
 try{
  command('--windows-migration-init-lab');
  assert.throws(()=>command('--windows-migration-init-lab'),'reusing a private rehearsal folder must fail');
  const from=sealMigrationCollections(source,key,{rootPin,role:'source'});
  const copy=sealMigrationCollections(structuredClone(source),key,{rootPin,role:'candidate'});
  command('--windows-migration-write-lab','source.sealed',from);
  command('--windows-migration-write-lab','candidate.sealed',copy);
  assert.throws(()=>command('--windows-migration-write-lab','candidate.sealed',copy),'existing snapshot must not be overwritten');
  assert.throws(()=>command('--windows-migration-read-lab','controller.pem'),'cannot read vault keys');
  const disk=readFileSync(join(dir,'candidate.sealed'));
  assert.equal(disk.includes(Buffer.from('sensitive historical text')),false);
  assert.equal(disk.includes(Buffer.from('synthetic encrypted message')),false);
  const reader=fileURLToPath(new URL('../scripts/migration-windows-readback-lab.mjs',import.meta.url));
  const input=JSON.stringify({labOnly:true,binary,binaryPin,dir,key:key.toString('hex'),rootPin});
  const run=()=>execFileSync(process.execPath,[reader],{input,windowsHide:true,timeout:20000,maxBuffer:4096,stdio:['pipe','pipe','ignore']});
  const report=JSON.parse(run().toString('utf8'));
  assert.equal(report.restartedProcessVerified,true);
  assert.equal(report.historicalCollectionsMatch,true);
  assert.equal(report.collections.messages.originalCount,1);
  assert.equal(report.collections.prekeys.originalCount,1);
  assert.equal(report.legacyDeletionAuthorized,false);
  assert.equal(report.liveRestoreAuthorized,false);
  assert.equal(report.durableTargetVerified,false);
  // Simulate corrupted candidate; source remains byte-for-byte unchanged,
  // with independently recoverable historical records.
  const tampered=Buffer.from(disk);tampered[30]^=1;
  writeFileSync(join(dir,'candidate.sealed'),tampered);
  assert.throws(run,'tampered target cannot pass independent readback');
  const sourceAfter=command('--windows-migration-read-lab','source.sealed');
  assert.deepEqual(sourceAfter,from);
  assert.deepEqual(openMigrationCollections(sourceAfter,key,{rootPin,role:'source'}),source);
 }finally{
  key.fill(0);
  if(existsSync(dir))rmSync(dir,{force:true,recursive:true});
 }
});
