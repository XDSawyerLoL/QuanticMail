import test from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import {
 migrationAuditName,sealMigrationAuditLabRecord,openMigrationAuditLabRecord,
 migrationAuditPacketHash,appendMigrationAuditLabRecord
} from '../lib/quantic/migration-audit-journal-lab.mjs';
const ctx={rootPin:'b'.repeat(64),transactionId:'c'.repeat(32)};
function store(map=new Map()){
 return{map,async probe(n){return map.has(n)?'present':'absent';},
 async read(n){assert.ok(map.has(n));return Buffer.from(map.get(n));},
 async write(n,b){assert.ok(!map.has(n),'forbid overwrite');map.set(n,Buffer.from(b));}};
}
const prepared={sourceManifestSha256:'1'.repeat(64),candidateManifestSha256:'2'.repeat(64)};
const verified={historicalCollectionsMatch:true,outboxPreserved:true,prekeysPreserved:true};
const observed={relayIdSha256:'3'.repeat(64),observedWindowSha256:'4'.repeat(64),
 observedRelayWindowStable:true,observedRelayWindowNotAtCap:true,
 pendingIncomingVisible:1,pendingReceiptsVisible:0};
test('encrypted create-only chained audit survives simulated process restart',async()=>{
 const key=randomBytes(32),s=store();
 const first=await appendMigrationAuditLabRecord(s,key,ctx,{sequence:0,phase:'prepared',facts:prepared});
 assert.equal(first.created,true);
 assert.equal(s.map.size,1);
 assert.equal(s.map.get(migrationAuditName(ctx.transactionId,0)).includes(Buffer.from('sourceManifestSha256')),false);
 const resumed=store(s.map);
 const next=await appendMigrationAuditLabRecord(resumed,key,ctx,{sequence:1,phase:'snapshot-verified',facts:verified});
 assert.equal(next.created,true);
 assert.equal((await appendMigrationAuditLabRecord(resumed,key,ctx,{sequence:1,phase:'snapshot-verified',facts:verified})).created,false);
 const remote=await appendMigrationAuditLabRecord(resumed,key,ctx,{sequence:2,phase:'relay-observed',facts:observed});
 assert.equal(remote.created,true);
 assert.equal(remote.liveRestoreAuthorized,false);
 assert.equal(remote.legacyDeletionAuthorized,false);
 assert.equal(s.map.size,3);
 key.fill(0);
});
test('tampered or absent predecessor prevents a resumed receipt; never repairs or overwrites',async()=>{
 const key=randomBytes(32),s=store();
 await appendMigrationAuditLabRecord(s,key,ctx,{sequence:0,phase:'prepared',facts:prepared});
 const target=migrationAuditName(ctx.transactionId,0);
 const old=Buffer.from(s.map.get(target));
 const tampered=Buffer.from(old);tampered[130]^=1;s.map.set(target,tampered);
 await assert.rejects(appendMigrationAuditLabRecord(s,key,ctx,{sequence:1,phase:'snapshot-verified',facts:verified}));
 assert.equal(s.map.size,1);assert.deepEqual(s.map.get(target),tampered);
 s.map.delete(target);
 await assert.rejects(appendMigrationAuditLabRecord(s,key,ctx,{sequence:1,phase:'snapshot-verified',facts:verified}));
 key.fill(0);
});
test('wrong key, root pin, tx and phase; duplicate altered facts fail closed',async()=>{
 const key=randomBytes(32),s=store();
 const p={sequence:0,phase:'prepared',previousHash:'0'.repeat(64),facts:prepared};
 const packet=sealMigrationAuditLabRecord(p,key,ctx);
 assert.ok(migrationAuditPacketHash(packet).match(/^[a-f0-9]{64}$/));
 assert.deepEqual(openMigrationAuditLabRecord(packet,key,ctx,p).facts,prepared);
 assert.throws(()=>openMigrationAuditLabRecord(packet,randomBytes(32),ctx,p));
 assert.throws(()=>openMigrationAuditLabRecord(packet,key,{...ctx,rootPin:'d'.repeat(64)},p));
 assert.throws(()=>openMigrationAuditLabRecord(packet,key,{...ctx,transactionId:'e'.repeat(32)},p));
 assert.throws(()=>sealMigrationAuditLabRecord({...p,phase:'relay-observed'},key,ctx));
 assert.throws(()=>sealMigrationAuditLabRecord({...p,facts:{authToken:'secret'}},key,ctx));
 assert.throws(()=>sealMigrationAuditLabRecord({...p,facts:{historicalMessageId:'private'}},key,ctx));
 await appendMigrationAuditLabRecord(s,key,ctx,p);
 await assert.rejects(appendMigrationAuditLabRecord(s,key,ctx,{sequence:0,phase:'prepared',facts:{sourceManifestSha256:'f'.repeat(64)}}));
 key.fill(0);
});
