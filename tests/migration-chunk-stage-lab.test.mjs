import test from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import {stageChunkedMigrationSnapshot} from '../lib/quantic/migration-chunk-stage-lab.mjs';
const pin='1'.repeat(64),transactionId='a'.repeat(32);
const info={rootPin:pin,transactionId,role:'c'};
const fixture=()=>({messages:[{id:'m1',body:'Z'.repeat(200000)}],
 contacts:[{handle:'synthetic',address:'test@example.invalid'}],
 prekeys:[{preKeyId:'prekey1',state:'claimed',privateKey:{d:'test'}}],
 outbox:[{id:'out1',ciphertext:'synthetic'}]});
const fakeStorage=(map=new Map())=>({
 map,async probe(name){return map.has(name)?'present':'absent';},
 async read(name){assert.ok(map.has(name));return Buffer.from(map.get(name));},
 async write(name,buffer){assert.equal(map.has(name),false,'never overwrite');map.set(name,Buffer.from(buffer));}
});
test('resume interrupted chunk copy with unchanged encrypted records',async()=>{
 const key=randomBytes(32),storage=fakeStorage(),source=fixture();
 const partial=await stageChunkedMigrationSnapshot(source,key,info,storage,{maxNewChunks:1});
 assert.equal(partial.complete,false);assert.equal(partial.staged,1);
 const resumed=await stageChunkedMigrationSnapshot(fixture(),key,info,fakeStorage(storage.map));
 assert.equal(resumed.complete,true);assert.equal(resumed.reused,1);assert.equal(resumed.total,3);
 const repeat=await stageChunkedMigrationSnapshot(fixture(),key,info,fakeStorage(storage.map));
 assert.equal(repeat.reused,3);assert.equal(repeat.complete,true);
 assert.equal(repeat.legacyDeletionAuthorized,false);
 key.fill(0);
});
test('modified existing partial ciphertext refuses without repair or overwrite',async()=>{
 const key=randomBytes(32),storage=fakeStorage();
 await stageChunkedMigrationSnapshot(fixture(),key,info,storage,{maxNewChunks:1});
 const name=[...storage.map.keys()][0],changed=Buffer.from(storage.map.get(name));
 changed[100]^=1;storage.map.set(name,changed);
 await assert.rejects(stageChunkedMigrationSnapshot(fixture(),key,info,storage),/refused|authenticate/i);
 assert.deepEqual(storage.map.get(name),changed);
 key.fill(0);
});
test('changed expected records or wrong trusted root cannot resume old transaction',async()=>{
 const key=randomBytes(32),storage=fakeStorage();
 await stageChunkedMigrationSnapshot(fixture(),key,info,storage,{maxNewChunks:1});
 const changed=fixture();changed.messages[0].body+='X';
 await assert.rejects(stageChunkedMigrationSnapshot(changed,key,info,storage),/refused|authenticate/i);
 await assert.rejects(stageChunkedMigrationSnapshot(fixture(),key,{...info,rootPin:'2'.repeat(64)},storage),/refused|authenticate/i);
 key.fill(0);
});
