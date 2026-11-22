import test from 'node:test';
import assert from 'node:assert/strict';
import {decideQuanticDurableRoute,allowedRelayHeaders,
 STATEFUL_QUANTIC_PATHS} from '../lib/quantic/durable-web-relay-route.mjs';
const web='https://quanticmail.onrender.com',relay='https://quanticmail-network-relay.onrender.com';
test('all 13 legacy identity/device/mail endpoints require one durable origin in production',()=>{
 assert.equal(STATEFUL_QUANTIC_PATHS.length,13);
 for(const p of STATEFUL_QUANTIC_PATHS){
  assert.deepEqual(decideQuanticDurableRoute(p,web,relay,true,true),
   {kind:'durable',origin:relay},p);
  assert.equal(decideQuanticDurableRoute(p,web,relay,true,false).kind,'refuse',p);
  assert.equal(decideQuanticDurableRoute(p,web,undefined,true,true).kind,'refuse',p);
  assert.equal(decideQuanticDurableRoute(p,web,relay,false,false).kind,'legacy-dev',p);
 }
 assert.equal(decideQuanticDurableRoute('/api/quantic/health',web,undefined,true).kind,'unmanaged');
 assert.equal(decideQuanticDurableRoute('/api/quantic/native/v1/send',web,relay,true,true).kind,'unmanaged');
});
test('durable endpoint is strictly HTTPS exact-origin and never a fallback to Web or loopback',()=>{
 for(const malicious of [
  '',web,web+'/',relay+'/',relay+'/api',relay+'?src=private',
  'http://quanticmail-network-relay.onrender.com',
  'https://relay.test@evil.test','https://relay.test:bad',
  'http://127.0.0.1:8787','https://127.0.0.1:8787',
  'https://localhost:8787','https://[::1]:8787','file:///tmp/relay',
  'https://relay.test/#private','https://relay.test/../private'
 ]){
  assert.equal(decideQuanticDurableRoute('/api/quantic/send',web,malicious,true,true).kind,
   'refuse','bad upstream: '+malicious);
 }
 assert.equal(decideQuanticDurableRoute('/api/quantic/send',web,'https://relay.example:9443',true,true).kind,'durable');
});
test('proxy cannot forward browser session cookies or attacker controlled forwarding metadata',()=>{
 const h=new Headers({
  authorization:'Bearer synthetic-token',accept:'application/json',
  'content-type':'application/json',cookie:'qm_session_v2=secret',
  origin:'https://evil.example','x-forwarded-for':'1.2.3.4',
  'x-internal-admin':'yes','x-forwarded-host':'localhost',
  'sec-fetch-site':'same-origin'
 });
 const filtered=allowedRelayHeaders(h);
 assert.equal(filtered.get('authorization'),'Bearer synthetic-token');
 assert.equal(filtered.get('content-type'),'application/json');
 assert.equal(filtered.get('accept'),'application/json');
 assert.equal(filtered.get('accept-encoding'),'identity');
 for(const k of ['cookie','origin','x-forwarded-for','x-forwarded-host','x-internal-admin','sec-fetch-site']){
  assert.equal(filtered.has(k),false,k);
 }
});
