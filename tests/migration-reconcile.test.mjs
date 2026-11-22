import test from 'node:test';
import assert from 'node:assert/strict';
import {reconcileHistoricalCollections} from '../lib/quantic/migration-reconcile.mjs';

const fixture=()=>({
 messages:[{id:'m-1',direction:'in',body:'historic secret',createdAt:'2026-11-20T00:00:00Z'}],
 contacts:[{handle:'contact',address:'someone@quantic',devices:[{deviceId:'d-1'}]}],
 prekeys:[{preKeyId:'p-1',state:'claimed',privateKey:{d:'secret'}}],
 outbox:[{id:'o-1',ciphertext:'original',lastAttemptAt:'2026-11-20T01:00:00Z'}]
});
const clone=x=>structuredClone(x);
test('complete independently copied collection snapshot passes but never authorizes deletion',()=>{
 const old=fixture(),candidate=clone(old);
 const r=reconcileHistoricalCollections(old,candidate);
 assert.equal(r.historicalCollectionsMatch,true);
 assert.equal(r.collections.messages.exact,true);
 assert.equal(r.collections.prekeys.exact,true);
 for(const flag of ['liveRegistrationAuthorized','liveRestoreAuthorized','legacyDeletionAuthorized','durableTargetVerified','remoteQueueReconciled'])assert.equal(r[flag],false);
 assert.equal(JSON.stringify(r).includes('historic secret'),false);
 assert.equal(JSON.stringify(r).includes('secret'),false);
});
test('missing messages and pending sends are counted without revealing identifiers',()=>{
 const old=fixture(),candidate=clone(old);
 candidate.messages=[];candidate.outbox=[];
 const r=reconcileHistoricalCollections(old,candidate);
 assert.equal(r.historicalCollectionsMatch,false);
 assert.equal(r.collections.messages.missing,1);
 assert.equal(r.collections.outbox.missing,1);
 assert.equal(JSON.stringify(r).includes('m-1'),false);
});
test('modified claimed prekey and contact are not accepted',()=>{
 const old=fixture(),candidate=clone(old);
 candidate.prekeys[0].state='unused';
 candidate.contacts[0].devices[0].deviceId='other';
 const r=reconcileHistoricalCollections(old,candidate);
 assert.equal(r.historicalCollectionsMatch,false);
 assert.equal(r.collections.prekeys.modified,1);
 assert.equal(r.collections.contacts.modified,1);
});
test('unexpected outbox item and duplicate keys fail closed',()=>{
 const old=fixture(),candidate=clone(old);
 candidate.outbox.push({id:'o-2',ciphertext:'unexpected'});
 assert.equal(reconcileHistoricalCollections(old,candidate).collections.outbox.unexpected,1);
 candidate.messages.push(clone(candidate.messages[0]));
 assert.throws(()=>reconcileHistoricalCollections(old,candidate),/refused/);
});
test('refuse comparing the same source object or shared collection arrays',()=>{
 const old=fixture();assert.throws(()=>reconcileHistoricalCollections(old,old),/refused/);
 const candidate=clone(old);candidate.messages=old.messages;
 assert.throws(()=>reconcileHistoricalCollections(old,candidate),/refused/);
});
test('reject malformed records, excess rows and unsupported values',()=>{
 const old=fixture(),candidate=clone(old);
 candidate.messages[0].body=Infinity;
 assert.throws(()=>reconcileHistoricalCollections(old,candidate),/refused/);
 candidate.messages[0].body='ok';
 candidate.messages[0].id='';
 assert.throws(()=>reconcileHistoricalCollections(old,candidate),/refused/);
 candidate.messages=Array.from({length:10001},(_,id)=>({id:String(id)}));
 assert.throws(()=>reconcileHistoricalCollections(old,candidate),/refused/);
});
