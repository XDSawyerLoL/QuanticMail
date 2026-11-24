import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,mkdirSync,writeFileSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {verifyNativePayload} from '../scripts/verify-native-payload-boundary.mjs';

test('staged payload accepts native modules and rejects legacy Web paths and dependencies',()=>{
 const root=mkdtempSync(join(tmpdir(),'quantic-native-payload-'));
 try{
  mkdirSync(join(root,'lib','quantic'),{recursive:true});
  const file=join(root,'lib','quantic','native.mjs');
  writeFileSync(file,'export const native=true;');
  assert.equal(verifyNativePayload(root),true);
  const old=join(root,'lib','quantic','durable-web-relay-route.mjs');
  writeFileSync(old,'export const legacy=true;');
  assert.throws(()=>verifyNativePayload(root),/Legacy Web payload refused/);
  rmSync(old);
  writeFileSync(file,"import './durable-web-relay-route.mjs';");
  assert.throws(()=>verifyNativePayload(root),/Legacy Web route reference refused/);
  writeFileSync(file,'export const native=true;');
  for(const endpoint of ['https://quanticmail.onrender.com','https://QUANTICMAIL-NETWORK-RELAY.ONRENDER.COM','https://quantic-network-relay-backup-production.up.railway.app','https://quantic-hostinger-relay.invalid']){
   writeFileSync(file,JSON.stringify({endpoint}));
   assert.throws(()=>verifyNativePayload(root),/Legacy hosted endpoint refused/);
  }
  writeFileSync(file,"export const endpoint='http://127.0.0.1:8787';");
  assert.equal(verifyNativePayload(root),true);
  const shortcut=join(root,'legacy.URL');
  writeFileSync(shortcut,'[InternetShortcut]');
  assert.throws(()=>verifyNativePayload(root),/Legacy Web payload refused/);
  rmSync(shortcut);
  mkdirSync(join(root,'lib','APP'));
  assert.throws(()=>verifyNativePayload(root),/Legacy Web payload refused/);
 }finally{rmSync(root,{recursive:true,force:true});}
});
