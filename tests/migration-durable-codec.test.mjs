import test from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import {sealMigrationCollections,openMigrationCollections} from '../lib/quantic/migration-durable-lab.mjs';
import {reconcileHistoricalCollections} from '../lib/quantic/migration-reconcile.mjs';
const fixture=()=>({
 messages:[{id:'m1',body:'historical mail — never on disk in plaintext'}],
 contacts:[{handle:'contact1',address:'synthetic@example.invalid'}],
 prekeys:[{preKeyId:'old-key',state:'claimed',privateKey:{d:'synthetic-secret'}}],
 outbox:[{id:'pending1',ciphertext:'synthetic-encrypted-outgoing'}]
});
const rootPin='a'.repeat(64);
test('sealed copy restores every historical record with no cutover grant',()=>{
 const key=randomBytes(32),original=fixture();
 const sealed=sealMigrationCollections(original,key,{rootPin,role:'candidate'});
 assert.equal(sealed.includes(Buffer.from('historical mail')),false);
 assert.equal(sealed.includes(Buffer.from('synthetic-secret')),false);
 const restored=openMigrationCollections(sealed,key,{rootPin,role:'candidate'});
 assert.deepEqual(restored,original);
 const comparison=reconcileHistoricalCollections(original,restored);
 assert.equal(comparison.historicalCollectionsMatch,true);
 assert.equal(comparison.legacyDeletionAuthorized,false);
 assert.equal(comparison.liveRestoreAuthorized,false);
});
test('wrong role, pin, key and altered ciphertext refuse',()=>{
 const key=randomBytes(32),sealed=sealMigrationCollections(fixture(),key,{rootPin,role:'source'});
 for(const [otherKey,scope] of [
  [key,{rootPin,role:'candidate'}],
  [key,{rootPin:'b'.repeat(64),role:'source'}],
  [randomBytes(32),{rootPin,role:'source'}]
 ])assert.throws(()=>openMigrationCollections(sealed,otherKey,scope));
 const changed=JSON.parse(sealed.toString('utf8'));
 changed.ciphertext=(changed.ciphertext[0]==='a'?'b':'a')+changed.ciphertext.slice(1);
 assert.throws(()=>openMigrationCollections(Buffer.from(JSON.stringify(changed)),key,{rootPin,role:'source'}));
});
test('claimed prekey cannot silently reactivate',()=>{
 const key=randomBytes(32),old=fixture(),changed=fixture();
 changed.prekeys[0].state='unused';
 const restored=openMigrationCollections(sealMigrationCollections(changed,key,{rootPin,role:'candidate'}),key,{rootPin,role:'candidate'});
 const report=reconcileHistoricalCollections(old,restored);
 assert.equal(report.historicalCollectionsMatch,false);
 assert.equal(report.collections.prekeys.modified,1);
});
