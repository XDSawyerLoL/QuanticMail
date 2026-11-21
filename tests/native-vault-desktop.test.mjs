import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,writeFile,readFile,rm,symlink} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {generateKeyPairSync,randomBytes} from 'node:crypto';
import {openReceipt,sealReceipt} from '../desktop/native-receipt-store.mjs';
import {runNativeDesktop,safeMailDisplay} from '../desktop/native-vault-desktop.mjs';
function dialogFor({files=[],responses=[],save}={}){
 const seen=[];
 return {seen,async showMessageBox(o){seen.push(o);return {response:responses.shift()??0};},async showOpenDialog(){const f=files.shift();return {canceled:!f,filePaths:f?[f]:[]};},async showSaveDialog(){return {canceled:!save,filePath:save};}};
}
async function fixture(fn){
 const dir=await mkdtemp(join(tmpdir(),'quantic-native-ui-'));
 try{
 const cfg=join(dir,'cfg.json'),env=join(dir,'envelope.json');
 await writeFile(cfg,JSON.stringify({labOnly:true}),{mode:0o600});
 const key=generateKeyPairSync('ec',{namedCurve:'prime256v1'});
 const e={keyMode:'static-fallback',ciphertext:Buffer.alloc(16).toString('base64'),iv:Buffer.alloc(12).toString('base64'),ephemeralPublicKey:key.publicKey.export({format:'jwk'})};
 await writeFile(env,JSON.stringify(e));
 await fn({dir,cfg,env,e});
 }finally{await rm(dir,{recursive:true,force:true});}
}
test('native dialog displays unverified plaintext and closes controller',()=>fixture(async({cfg,env})=>{
 const d=dialogFor({files:[cfg,env],responses:[0,1]});let closed=0;
 const result=await runNativeDesktop(d,{connect:async()=>({openStatic:async()=>({subject:'test',body:'synthetic'}),close:()=>closed++})});
 assert.equal(result,'completed');assert.equal(closed,1);assert.match(d.seen.at(-1).message,/non vérifié/);assert.match(d.seen.at(-1).detail,/synthetic/);
}));
test('cancel, hybrid mode and nonprivate config never call broker',()=>fixture(async({cfg,env,e,dir})=>{
 let calls=0;const connect=async()=>{calls++;throw Error('unexpected');};
 assert.equal(await runNativeDesktop(dialogFor({files:[cfg,env],responses:[0,0]}),{connect}),'cancelled');
 await writeFile(env,JSON.stringify({...e,keyMode:'one-time-prekey'}));
 assert.equal(await runNativeDesktop(dialogFor({files:[cfg,env],responses:[0,1]}),{connect}),'failed');
 const link=join(dir,'link');await symlink(cfg,link);
 assert.equal(await runNativeDesktop(dialogFor({files:[link,env],responses:[0,1]}),{connect}),'failed');
 assert.equal(calls,0);
}));
test('broker failure does not display plaintext or fall back',()=>fixture(async({cfg,env})=>{
 const d=dialogFor({files:[cfg,env],responses:[0,1]});let closed=0;
 assert.equal(await runNativeDesktop(d,{connect:async()=>({openStatic:async()=>{throw Error('SECRET');},close:()=>closed++})}),'failed');
 assert.equal(closed,1);assert.ok(!JSON.stringify(d.seen).includes('SECRET'));assert.match(d.seen.at(-1).message,/non confirmée/);
}));
test('signature output is exclusive and proof only',()=>fixture(async({cfg,env,dir})=>{
 const path=join(dir,'proof');let calls=0;const connect=async()=>({signEnrollment:async()=>{calls++;return 'a'.repeat(128);},close(){}});
 assert.equal(await runNativeDesktop(dialogFor({files:[cfg,env],responses:[1,1],save:path}),{connect}),'completed');
 assert.equal(JSON.parse(await readFile(path,'utf8')),'a'.repeat(128));
 assert.equal(await runNativeDesktop(dialogFor({files:[cfg,env],responses:[1,1],save:path}),{connect}),'failed');assert.equal(calls,1);
}));
test('message display neutralizes directional overrides and rejects other payloads',()=>{
 assert.equal(safeMailDisplay({subject:'x\u202e',body:'hello'}),'Objet : x<U+202E>\n\nhello');
 assert.throws(()=>safeMailDisplay({body:'message'}));
});

test('native mailbox receive requires local consent, saves before ack and refuses wrong account',()=>fixture(async({cfg,dir})=>{
 const path=join(dir,'received.json'),payload={subject:'test',body:'received'},item={id:'01234567-89ab-4cde-8fab-0123456789ab',digest:'f'.repeat(64),record:{}};
 const address='alice~'+'a'.repeat(32)+'@quantic',deviceId='d-'+'b'.repeat(32);
 const receiptKeyFile=join(dir,'receipt.key'),key=randomBytes(32);await writeFile(receiptKeyFile,key,{mode:0o600});
 const config={labOnly:true,pqMode:{enabled:true,address,deviceId,receiptKeyFile},nativeRelay:{address,deviceId}};
 await writeFile(cfg,JSON.stringify(config),{mode:0o600});
 let ack=0,opens=0,clients=0;
 const mailboxConnect=async()=>{clients++;return {pull:async()=>item,ack:async(id,digest)=>{assert.equal(id,item.id);assert.equal(digest,item.digest);const encrypted=JSON.parse(await readFile(path,'utf8'));assert.equal(encrypted.payload,undefined);assert.deepEqual(openReceipt(key,config.nativeRelay,encrypted),{id,digest,payload});ack++;}};};
 const connect=async()=>({openHybrid:async()=>{opens++;return payload;},close(){}});
 assert.equal(await runNativeDesktop(dialogFor({files:[cfg],responses:[0,3,0],save:path}),{connect,mailboxConnect}),'cancelled');
 assert.equal(opens,0);assert.equal(ack,0);
 assert.equal(await runNativeDesktop(dialogFor({files:[cfg],responses:[0,3,1],save:path}),{connect,mailboxConnect}),'completed');
 assert.equal(opens,1);assert.equal(ack,1);
 await writeFile(cfg,JSON.stringify({...config,nativeRelay:{...config.nativeRelay,deviceId:'d-'+'c'.repeat(32)}}));
 assert.equal(await runNativeDesktop(dialogFor({files:[cfg],responses:[0,3,1]}),{connect,mailboxConnect}),'failed');
 assert.equal(clients,2);
}));

test('receipt encryption binds account, message ID and digest and refuses modified tags',()=>{
 const key=randomBytes(32),scope={address:'alice~'+'a'.repeat(32)+'@quantic',deviceId:'d-'+'b'.repeat(32)},item={id:'01234567-89ab-4cde-8fab-0123456789ab',digest:'f'.repeat(64)},payload={subject:'private',body:'secret'};
 const a=sealReceipt(key,scope,item,payload),b=sealReceipt(key,scope,item,payload);
 assert.notEqual(a.iv,b.iv);assert.deepEqual(openReceipt(key,scope,a),{...item,payload});
 for(const bad of [{...a,digest:'e'.repeat(64)},{...a,tag:Buffer.alloc(16).toString('base64url')},{...a,address:'bobby~'+'a'.repeat(32)+'@quantic'}])assert.throws(()=>openReceipt(key,scope,bad));
 assert.throws(()=>openReceipt(randomBytes(32),scope,a));key.fill(0);
});
