import test from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import {sealChunkedMigrationSnapshot,openChunkedMigrationSnapshot,migrationChunkFileName,MIGRATION_CHUNK_LAB_LIMITS} from '../lib/quantic/migration-chunked-lab.mjs';
const rootPin='a'.repeat(64),transactionId='b'.repeat(32);
const fixture=body=>({messages:[{id:'historic-1',body}],contacts:[{handle:'contact',address:'synthetic@example.invalid'}],
 prekeys:[{preKeyId:'claimed-1',state:'claimed',privateKey:{d:'synthetic-only'}}],
 outbox:[{id:'queued-1',ciphertext:'synthetic'}]});
const scope=role=>({rootPin,transactionId,role});
test('16 MiB boundary snapshot roundtrips with authenticated independent chunks',()=>{
 const key=randomBytes(32);
 const base=fixture('');
 const baseBytes=Buffer.byteLength(JSON.stringify(base));
 const body='Z'.repeat(MIGRATION_CHUNK_LAB_LIMITS.maxPlainBytes-baseBytes-1);
 const original=fixture(body);
 assert.equal(Buffer.byteLength(JSON.stringify(original)),MIGRATION_CHUNK_LAB_LIMITS.maxPlainBytes-1);
 const sealed=sealChunkedMigrationSnapshot(original,key,scope('s'));
 assert.equal(sealed.chunks.length,MIGRATION_CHUNK_LAB_LIMITS.maxChunks);
 assert.ok(sealed.chunks.every(c=>c.length<=131072));
 assert.equal(sealed.manifest.includes(Buffer.from(body.slice(0,100))),false);
 assert.deepEqual(openChunkedMigrationSnapshot(sealed,key,scope('s')),original);
 assert.throws(()=>sealChunkedMigrationSnapshot(fixture(body+'extra'),key,scope('s')),/refused/);
 key.fill(0);
});
test('tamper, truncation, reorder, wrong role/root and fake manifest fail closed',()=>{
 const key=randomBytes(32),s=sealChunkedMigrationSnapshot(fixture('Q'.repeat(150000)),key,scope('c'));
 assert.equal(s.chunks.length,2);
 assert.throws(()=>openChunkedMigrationSnapshot(s,key,scope('s')),/refused|authenticate/i);
 assert.throws(()=>openChunkedMigrationSnapshot(s,key,{...scope('c'),rootPin:'1'.repeat(64)}),/refused|authenticate/i);
 assert.throws(()=>openChunkedMigrationSnapshot({...s,chunks:s.chunks.slice(1)},key,scope('c')),/refused/);
 assert.throws(()=>openChunkedMigrationSnapshot({...s,chunks:s.chunks.toReversed()},key,scope('c')),/refused|authenticate/i);
 const changed=JSON.parse(s.chunks[0].toString());
 changed.ciphertext=(changed.ciphertext[0]==='A'?'B':'A')+changed.ciphertext.slice(1);
 assert.throws(()=>openChunkedMigrationSnapshot({...s,chunks:[Buffer.from(JSON.stringify(changed)),s.chunks[1]]},key,scope('c')),/refused|authenticate/i);
 const marker=JSON.parse(s.manifest);
 marker.total=1;
 assert.throws(()=>openChunkedMigrationSnapshot({...s,manifest:Buffer.from(JSON.stringify(marker))},key,scope('c')),/refused|authenticate/i);
 key.fill(0);
});
test('canonical role-scoped file names cannot target account keys or traversal',()=>{
 assert.equal(migrationChunkFileName(transactionId,'c',10),'m-'+transactionId+'-c-010.enc');
 assert.equal(migrationChunkFileName(transactionId,'s','manifest'),'m-'+transactionId+'-s-manifest.enc');
 for(const x of ['../controller.pem','manifest.pem',-1,999999])assert.throws(()=>migrationChunkFileName(transactionId,'s',x));
 assert.throws(()=>migrationChunkFileName(transactionId,'x',0));
});
