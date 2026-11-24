import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,randomBytes} from 'node:crypto';
import {win32} from 'node:path';
import {composeAndSendWindowsLab} from '../desktop/native-windows-integrated-mail.mjs';
import {runWindowsScatteringMail} from '../desktop/native-windows-mail-flow.mjs';
import {nativeRecordDigest} from '../lib/quantic/native-mailbox.mjs';

const dir='C:\\Quantic\\private';
const alice='alice~'+'a'.repeat(32)+'@quantic',bob='bobby~'+'b'.repeat(32)+'@quantic';
const device='d-'+'c'.repeat(32),other='d-'+'d'.repeat(32);
const ctx={clientMessageId:'synthetic-2026-00000001',from:alice,fromDeviceId:device,to:bob,toDeviceId:other};
const draft={context:ctx,payload:{subject:'Laboratory only',body:'PRIVATE test message'}};
const input=win32.join(dir,'draft-proposal.json'),output=win32.join(dir,'wire-confirmed.json');
const cfg={windowsLab:{dir},pqMode:{enabled:true,address:alice,deviceId:device},
 windowsScattering:{enabled:true,address:alice,deviceId:device,
 receiptKeyFile:win32.join(dir,'receipt.key'),endpoint:'http://127.0.0.1:49510/',token:'A'.repeat(64)}};
const {publicKey}=generateKeyPairSync('ec',{namedCurve:'prime256v1'});
const jwk=publicKey.export({format:'jwk'});
function fakeSigned(context=ctx){
 return {
  format:'quantic-native-mail',version:1,context:{...context},
  envelope:{cryptoSuite:'QNT-HYB-P256-MLKEM768-HKDFSHA256-AES256GCM-1',
   keyMode:'hybrid-static-fallback',
   classicalEphemeralPublicKey:{kty:'EC',crv:'P-256',x:jwk.x,y:jwk.y},
   pqKemCiphertext:randomBytes(1088).toString('base64url'),
   iv:randomBytes(12).toString('base64url'),
   ciphertext:randomBytes(32).toString('base64url')},
  senderAuth:{classicalSignature:randomBytes(64).toString('base64url'),
   pqSignature:randomBytes(3309).toString('base64url')}
 };
}
function setup({approve=async()=>true,failWrite=false,corrupt=false,failSend=false,identity=ctx,recover=false}={}){
 const files=new Map([[input,Buffer.from(JSON.stringify(draft))]]);
 let write=0,seal=0,close=0,sends=0,reads=0,approvals=0;
 const signed=fakeSigned(identity);
 const storage={
  async read(path){
   reads++;
   assert.ok(files.has(path),'write must precede readback');
   const b=Buffer.from(files.get(path));
   if(corrupt&&path===output)b[0]^=1;
   return b;
  },
  async writeWire(path,bytes){
   assert.equal(path,output);assert.equal(files.has(path),false,'must never overwrite');
   if(failWrite)throw Error('native NTFS sync failed');
   files.set(path,Buffer.from(bytes));write++;
  }
 };
 const deps={
  input,output,recover,
  approve:async p=>{approvals++;return approve(p,approvals);},
  connect:async()=>({async sealHybrid(context,payload,options){
   seal++;assert.deepEqual(context,ctx);assert.deepEqual(payload,draft.payload);
   assert.equal(options.recover,recover);
   return signed;
  },close(){close++;}}),
  mailboxFactory:async scope=>{
   assert.equal(scope.address,alice);return {async send(r){
    sends++;assert.deepEqual(r,signed);
    if(failSend)throw Error('ambiguous transport delivery');
    return{id:'01234567-89ab-4cde-8fab-0123456789ab',digest:nativeRecordDigest(r),status:'queued'};
   }};
  }
 };
 return{storage,deps,files,stats:()=>({write,seal,close,sends,reads,approvals}),signed};
}
test('Windows compose/send: exact native wire written and read back before one explicit relay send',async()=>{
 const x=setup();
 const result=await composeAndSendWindowsLab(cfg,x.storage,x.deps);
 assert.equal(result.status,'deposited');
 assert.equal(result.relayStatus,'queued');
 assert.equal(result.digest,nativeRecordDigest(x.signed));
 assert.equal(result.wireFile,'wire-confirmed.json');
 assert.equal(result.liveRestoreAuthorized,false);
 assert.equal(result.legacyDeletionAuthorized,false);
 assert.deepEqual(x.stats(),{write:1,seal:1,close:1,sends:1,reads:2,approvals:2});
 assert.deepEqual(JSON.parse(x.files.get(output)),x.signed);
 assert.deepEqual(JSON.parse(x.files.get(input)),draft,'draft remains intact');
});
test('Declining final send still creates exactly one reusable signed wire',async()=>{
 const x=setup({approve:async (_,n)=>n===1});
 const result=await composeAndSendWindowsLab(cfg,x.storage,x.deps);
 assert.equal(result.status,'saved-not-sent');
 assert.equal(x.stats().sends,0);assert.equal(x.stats().write,1);
 assert.equal(result.wireFile,'wire-confirmed.json');
});
test('Declining sealing or invalid account never touches native signing nor network',async()=>{
 const x=setup({approve:async()=>false});
 assert.equal((await composeAndSendWindowsLab(cfg,x.storage,x.deps)).status,'cancelled-before-seal');
 assert.equal(x.stats().seal,0);assert.equal(x.stats().write,0);assert.equal(x.stats().sends,0);
 const bad=setup();
 bad.files.set(input,Buffer.from(JSON.stringify({context:{...ctx,from:bob},payload:draft.payload})));
 await assert.rejects(composeAndSendWindowsLab(cfg,bad.storage,bad.deps));
 assert.equal(bad.stats().seal,0);
 await assert.rejects(composeAndSendWindowsLab({...cfg,windowsScattering:{...cfg.windowsScattering,endpoint:'https://remote.example/'}},x.storage,x.deps));
});
test('Native disk write or readback tamper prevents any relay call; preserve draft',async()=>{
 for(const opts of [{failWrite:true},{corrupt:true}]){
  const x=setup(opts);
  await assert.rejects(composeAndSendWindowsLab(cfg,x.storage,x.deps));
  assert.equal(x.stats().sends,0);
  assert.deepEqual(JSON.parse(x.files.get(input)),draft);
 }
});
test('Ambiguous network failure never retries or deletes the signed wire',async()=>{
 const x=setup({failSend:true,recover:true});
 const pending=await composeAndSendWindowsLab(cfg,x.storage,x.deps);
 assert.equal(pending.status,'deposit-unconfirmed');
 assert.equal(pending.digest,nativeRecordDigest(x.signed));
 assert.equal(pending.wireFile,'wire-confirmed.json');
 assert.equal(pending.retryRequiresConfirmation,true);
 assert.equal(x.stats().sends,1);
 assert.equal(x.stats().write,1);
 assert.deepEqual(JSON.parse(x.files.get(output)),x.signed);
 const y=setup({identity:{...ctx,to:alice}});
 await assert.rejects(composeAndSendWindowsLab(cfg,y.storage,y.deps));
 assert.equal(y.stats().write,0);assert.equal(y.stats().sends,0);
 const mismatchedId=setup({identity:{...ctx,clientMessageId:'different-client-message-id-001'}});
 await assert.rejects(composeAndSendWindowsLab(cfg,mismatchedId.storage,mismatchedId.deps));
 assert.equal(mismatchedId.stats().write,0);
 assert.equal(mismatchedId.stats().sends,0);
});

test('explicit recovery of an unconfirmed send uses the same signed record and a fresh client',async()=>{
 const x=setup({failSend:true});
 const pending=await composeAndSendWindowsLab(cfg,x.storage,x.deps);
 const before=Buffer.from(x.files.get(output));
 let retries=0,opened=0;
 const deps={operation:'retry-send',path:output,expectedDigest:pending.digest,approve:async()=>true,
  connect:async()=>{throw Error('retry must not open signing vault');},
  mailboxFactory:async scope=>{opened++;assert.equal(scope.address,alice);
   return {send:async record=>{retries++;assert.deepEqual(record,x.signed);
    return {id:'01234567-89ab-4cde-8fab-0123456789ab',digest:pending.digest,status:'queued',duplicate:true};
   }};
  }};
 const answer=await runWindowsScatteringMail(cfg,x.storage,deps);
 assert.equal(answer.status,'deposited');assert.equal(answer.digest,pending.digest);
 assert.equal(retries,1);assert.equal(opened,1);assert.deepEqual(x.files.get(output),before);
 assert.equal(x.stats().seal,1);assert.equal(x.stats().write,1);
 await assert.rejects(runWindowsScatteringMail(cfg,x.storage,{...deps,expectedDigest:'0'.repeat(64)}));
 const cancelled=await runWindowsScatteringMail(cfg,x.storage,{...deps,approve:async()=>false});
 assert.equal(cancelled.status,'cancelled');assert.equal(retries,1);assert.equal(opened,1);
 await assert.rejects(runWindowsScatteringMail(cfg,x.storage,{...deps,approve:async()=>{
  x.files.set(output,Buffer.from(JSON.stringify(fakeSigned())));return true;
 }}));
 assert.equal(retries,1);assert.equal(opened,1);
});
test('malformed or missing recovery receipt stays unconfirmed, never auto-retries',async()=>{
 const x=setup({failSend:true});const pending=await composeAndSendWindowsLab(cfg,x.storage,x.deps);
 let attempts=0;
 const answer=await runWindowsScatteringMail(cfg,x.storage,{operation:'retry-send',path:output,
  expectedDigest:pending.digest,approve:async()=>true,mailboxFactory:async()=>({send:async()=>{
   attempts++;return {id:'bad',digest:pending.digest,status:'queued'};
  }})});
 assert.equal(answer.status,'deposit-unconfirmed');assert.equal(answer.retryRequiresConfirmation,true);
 assert.equal(attempts,1);assert.deepEqual(JSON.parse(x.files.get(output)),x.signed);
});
