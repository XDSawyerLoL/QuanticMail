import test from 'node:test';
import assert from 'node:assert/strict';
import {windowsLabPath,createWindowsNativeStorage} from '../desktop/native-windows-storage.mjs';
import {bindWindowsDesktopConfig,runWindowsNativeDesktop} from '../desktop/native-windows-desktop.mjs';
const dir='C:\\Quantic\\private',binary='C:\\Quantic\\bin\\Vault.exe',binarySha256='a'.repeat(64),boot={dir,binary,binarySha256};
const config={...boot,labOnly:true,pqMode:{enabled:true},windowsLab:{enabled:true,dir}};
test('Windows paths and independently supplied binary pin are bound',()=>{
 assert.equal(windowsLabPath(dir,dir+'\\desktop.json'),'desktop.json');
 for(const p of [dir+'\\..\\desktop.json',dir+'\\desktop.json:ads',dir+'\\controller.key','C:\\other\\desktop.json'])assert.throws(()=>windowsLabPath(dir,p));
 assert.equal(bindWindowsDesktopConfig(config,boot),config);
 for(const bad of [{binarySha256:'b'.repeat(64)},{nativeRelay:{}},{windowsLab:{enabled:false,dir}}])assert.throws(()=>bindWindowsDesktopConfig({...config,...bad},boot));
});
test('Windows helper activation is explicit and refuses missing binary pin',async()=>{await assert.rejects(createWindowsNativeStorage({...boot,binarySha256:''}));});
test('offline Windows UI writes only the sealed wire and passes exact recovery flag',async()=>{
 const path=dir+'\\draft-one.json',output=dir+'\\wire-one.json',payload={subject:'Synthetic',body:'Sensitive'};
 const record={context:{to:'alice~'+'a'.repeat(32)+'@quantic'},payload};let writes=0,closed=0;
 const d={async showMessageBox(o){return {response:o.message.startsWith('Coffre')?1:o.type==='warning'?2:0};},async showOpenDialog(){return {filePaths:[path]};},async showSaveDialog(){return {filePath:output};}};
 const result=await runWindowsNativeDesktop(d,boot,{makeStorage:async()=>({read:async p=>Buffer.from(JSON.stringify(p===path?record:config)),writeWire:async(p,b)=>{assert.equal(p,output);assert.deepEqual(JSON.parse(b),{ciphertext:'encrypted'});writes++;}}),connect:async()=>({sealHybrid:async(c,p,o)=>{assert.deepEqual(p,payload);assert.equal(o.recover,true);return {ciphertext:'encrypted'};},close(){closed++;}})});
 assert.equal(result,'completed');assert.equal(writes,1);assert.equal(closed,1);
});
