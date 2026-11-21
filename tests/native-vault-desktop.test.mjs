import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,writeFile,readFile,rm,symlink} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {generateKeyPairSync} from 'node:crypto';
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
