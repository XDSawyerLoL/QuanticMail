import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
import {createRequire} from 'node:module';
import vm from 'node:vm';
const require=createRequire(import.meta.url);
const {nativeStartupPolicy,canonicalWindowsPath}=require('../desktop/native-entry-policy.cjs');
const main=readFileSync(new URL('../desktop/main.cjs',import.meta.url),'utf8');
const policy=(args,platform='win32',nodeVersion='24.8.0',tty=false)=>
 nativeStartupPolicy(args,{platform,nodeVersion,tty});

function runEntrypoint(args,platform='win32'){
 const exits=[],dialogs=[],imports=[];
 const app={
  whenReady:()=>Promise.resolve(),
  exit:code=>exits.push(code),
  on:()=>{}
 };
 const dialog={showMessageBox:async o=>{dialogs.push(o);return {response:0}}};
 vm.runInNewContext(main,{
  require:name=>{
    imports.push(name);
    if(name==='electron')return {app,dialog};
    if(name==='./native-entry-policy.cjs')return {nativeStartupPolicy};
    throw Error('Unexpected runtime dependency: '+name);
  },
  process:{argv:args,platform,versions:{node:'24.8.0'},stderr:{isTTY:false}},
  console
 },{filename:'desktop/main.cjs'});
 return new Promise(resolve=>setImmediate(()=>resolve({exits,dialogs,imports})));
}
test('unconfigured Electron launch refuses Web site and quits without any browser renderer',async()=>{
 const r=await runEntrypoint(['QuanticMail.exe']);
 assert.deepEqual(r.exits,[2]);
 assert.equal(r.dialogs.length,1);
 assert.match(r.dialogs[0].message,/Web désactivé/);
 assert.equal(r.dialogs[0].noLink,true);
 assert.deepEqual(r.imports,['electron','./native-entry-policy.cjs']);
 assert.doesNotMatch(main,/\b(?:BrowserWindow|loadURL|loadFile|openExternal|MAIL_ORIGIN|PORTAL_ORIGIN)\b/);
});
test('URL passed as launch argument never restores remote application',async()=>{
 const r=await runEntrypoint(['QuanticMail.exe','https://quanticmail.onrender.com']);
 assert.deepEqual(r.exits,[2]);
 assert.equal(r.imports.includes('electron'),true);
});
test('conflicting and unpinned Windows bootstrap cannot reach broker or site',async()=>{
 const bin='C:\\Quantic Lab\\Vault.exe',dir='C:\\Quantic Lab\\private',pin='a'.repeat(64);
 const good=['QuanticMail.exe','--native-vault-windows-lab',bin,pin,dir];
 assert.deepEqual(policy(good),{mode:'windows-native-lab',binary:bin,binarySha256:pin,dir});
 for(const bad of [
  [...good,'--native-vault-lab'],
  [...good,'--native-vault-windows-lab'],
  [...good.slice(0,3),'WRONG',dir],
  [...good.slice(0,4),'\\\\remote\\share'],
  [...good.slice(0,4),'C:\\Quantic Lab\\..\\other'],
  [...good.slice(0,4),'C:\\Quantic Lab\\trailing.'],
  ['QuanticMail.exe','--native-vault-windows-lab',bin,pin],
 ]){
  assert.throws(()=>policy(bad),undefined,JSON.stringify(bad));
  const r=await runEntrypoint(bad);
  assert.deepEqual(r.exits,[1]);
  assert.equal(r.dialogs.length,1);
 }
 assert.throws(()=>policy(good,'linux'));
 assert.throws(()=>policy(good,'win32','22.0.0'));
 assert.ok(canonicalWindowsPath(bin));
 assert.equal(canonicalWindowsPath('https://example.com/key'),false);
});
test('Linux native entry requires local TTY and exact arguments',()=>{
 const good=['electron','--native-vault-lab'];
 assert.equal(policy(good,'linux','24.8.0',true).mode,'linux-native-lab');
 assert.throws(()=>policy(good,'linux','24.8.0',false));
 assert.throws(()=>policy([...good,'https://web.example'],'linux','24.8.0',true));
 assert.throws(()=>policy(good,'win32','24.8.0',true));
 assert.equal(policy(['QuanticMail.exe']).mode,'native-install-required');
});
test('obsolete Electron release path has no publisher permission and is blocked by default',()=>{
 const pkg=JSON.parse(readFileSync(new URL('../package.json',import.meta.url),'utf8'));
 assert.equal(pkg.scripts['desktop:dist'],'node scripts/refuse-legacy-electron-release.mjs');
 const workflow=readFileSync(new URL('../.github/workflows/desktop-release.yml',import.meta.url),'utf8');
 assert.match(workflow,/refuse-legacy-electron-release\.mjs/);
 assert.doesNotMatch(workflow,/gh release create|electron-builder|contents:\s*write/);
 const run=spawnSync(process.execPath,['scripts/refuse-legacy-electron-release.mjs'],{encoding:'utf8'});
 assert.equal(run.status,1);
 assert.match(run.stderr,/QUANTIC_NATIVE_ONLY/);
});
test('real native Windows Alpha installer still targets packaged offline launcher with independent binary digest',()=>{
 const nsi=readFileSync(new URL('../scripts/Quantic-Sillage-Alpha.nsi',import.meta.url),'utf8');
 const launcher=readFileSync(new URL('../scripts/Start-Windows-PQ-Lab.ps1',import.meta.url),'utf8');
 assert.match(nsi,/Start-Windows-PQ-Lab\.ps1/);
 assert.match(nsi,/TrustedBinarySha256/);
 assert.match(nsi,/ExpectedManifestSha256/);
 assert.match(launcher,/Test-Windows-PQ-Package\.ps1/);
 assert.match(launcher,/Get-FileHash/);
 assert.doesNotMatch(nsi,/https?:\/\//);
});
