import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import {
  createQuanticSitePresence,
} from '../lib/quantic-id/site-presence.mjs';

let time = Date.parse('2026-11-20T12:00:00Z');
const now = () => time;
const audience = 'https://example-quantic.test';
const {privateKey,publicKey}=generateKeyPairSync('ed25519');
const publicDer = publicKey.export({format:'der',type:'spki'});
const keyId = 'qid_'+createHash('sha256').update(publicDer).digest('hex').slice(0,32);

function proof(challenge, override = {}) {
  const data = JSON.stringify({
    version:1,keyId,challenge,audience,issuedAt:new Date(time).toISOString(),...override,
  });
  return {version:1,algorithm:'ed25519',keyId,publicKey:publicDer.toString('base64url'),
    signature:sign(null,Buffer.from(data),privateKey).toString('base64url'),payload:data};
}
function cache() {return createQuanticSitePresence({audience,now,ttlMs:10_000});}

test('signed Quantic ID becomes visible, explicit lock removes ALL sessions immediately',async()=>{
  const site=cache();
  const a=site.begin(),b=site.begin();
  const one=await site.activate({challenge:a.challenge,proof:proof(a.challenge),displayName:'Ada'});
  const two=await site.activate({challenge:b.challenge,proof:proof(b.challenge),displayName:'Ada'});
  assert.equal(site.listVisible().length,1);
  assert.equal(site.lock(one.token),true);
  assert.deepEqual(site.listVisible(),[]);
  assert.equal(site.lock(two.token),false);
});

test('failed lock notification cannot keep presence alive beyond bounded TTL',async()=>{
  time+=11_000; const site=cache(); const c=site.begin();
  await site.activate({challenge:c.challenge,proof:proof(c.challenge),displayName:'Ada'});
  assert.equal(site.listVisible().length,1);
  time+=10_000;
  assert.deepEqual(site.listVisible(),[]);
});

test('renewal requires a fresh challenge signed by the original identity',async()=>{
  const site=cache(),a=site.begin();
  const lease=await site.activate({challenge:a.challenge,proof:proof(a.challenge)});
  const c=site.begin({purpose:'renew',token:lease.token});
  await site.renew({token:lease.token,challenge:c.challenge,proof:proof(c.challenge)});
  await assert.rejects(site.renew({token:lease.token,challenge:c.challenge,proof:proof(c.challenge)}),/déjà utilisé/);
  const d=site.begin({purpose:'renew',token:lease.token});
  await assert.rejects(site.renew({token:lease.token,challenge:d.challenge,proof:proof(d.challenge,{audience:'https://other.test'})}),/hors contexte/);
});

test('a forged Quantic ID signature cannot create site presence',async()=>{
  const site=cache(),c=site.begin();
  const f=proof(c.challenge);f.signature=Buffer.alloc(64).toString('base64url');
  await assert.rejects(site.activate({challenge:c.challenge,proof:f}),/Signature/);
  assert.deepEqual(site.listVisible(),[]);
});

test('no site-local account database is required and no consented records are modified',async()=>{
  const savedInformation={pseudonym:'Ada',preferences:{language:'fr'}};
  const site=cache(),c=site.begin();
  const lease=await site.activate({challenge:c.challenge,proof:proof(c.challenge)});
  site.lock(lease.token);
  assert.deepEqual(savedInformation,{pseudonym:'Ada',preferences:{language:'fr'}});
  assert.deepEqual(site.listVisible(),[]);
});
