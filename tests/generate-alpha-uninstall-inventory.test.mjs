import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,mkdir,writeFile,readFile,rm,symlink} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createHash} from 'node:crypto';
import {generateAlphaUninstallInventory} from '../scripts/generate-alpha-uninstall-inventory.mjs';
const sha=b=>createHash('sha256').update(b).digest('hex');
async function fixture(){
 const dir=await mkdtemp(join(tmpdir(),'quantic-nsis-inventory-'));
 const paths=['app.ps1','bin/Vault.exe','bin/Pacer.exe','runtime/node.exe',
  'desktop/bridge.mjs','desktop/identity.mjs','scripts/verify.mjs',
  'scripts/launch.mjs','docs/guide.md','licenses/Node-LICENSE.txt',
  'licenses/openssl/LICENSE','lib/quantic/manifest.mjs','README.md','runtime/LICENSE.txt'];
 const entries=[];
 for(const [i,p] of paths.entries()){
  const path=join(dir,...p.split('/'));
  await mkdir(join(dir,...p.split('/').slice(0,-1)),{recursive:true});
  const b=Buffer.from('TEST-FIXTURE-CONTENT-'+i+'\n');
  await writeFile(path,b,{flag:'wx'});
  entries.push(sha(b)+' *./'+p);
 }
 await writeFile(join(dir,'SHA256SUMS.txt'),entries.join('\n')+'\n',{flag:'wx'});
 return {dir,paths,close:()=>rm(dir,{recursive:true,force:true})};
}
test('exact NSIS uninstall list contains only known build files and nonrecursive deepest-first empty directory deletion',async()=>{
 const f=await fixture();
 try{
  const generated=await generateAlphaUninstallInventory(f.dir);
  assert.match(generated,/Delete "\$INSTDIR\\app\\bin\\Vault\.exe"/);
  assert.match(generated,/Delete "\$INSTDIR\\app\\SHA256SUMS\.txt"/);
  assert.match(generated,/RMDir "\$INSTDIR\\app\\licenses\\openssl"/);
  assert.doesNotMatch(generated,/RMDir\s+\/r/i);
  assert.doesNotMatch(generated,/IdentityVaults|PrivateDirectory|AppData\\Roaming/);
  const deep=generated.indexOf('RMDir "$INSTDIR\\app\\licenses\\openssl"');
  const shallow=generated.indexOf('RMDir "$INSTDIR\\app\\licenses"');
  assert.ok(deep>=0&&shallow>deep);
  assert.equal(generated.split('\n').filter(x=>x.startsWith(' Delete ')).length,f.paths.length+1);
 }finally{await f.close();}
});
test('extra user content refuses generating a destructive list instead of extending deletion scope',async()=>{
 const f=await fixture();
 try{
  await writeFile(join(f.dir,'personal-keys.json'),Buffer.from('KEEP-THIS-DATA'));
  await assert.rejects(generateAlphaUninstallInventory(f.dir),/unsafe Alpha/);
 }finally{await f.close();}
});
test('tampered manifest, modified binary and swapped hard link each fail closed',async()=>{
 const f=await fixture();
 try{
  await writeFile(join(f.dir,'bin','Vault.exe'),'MALICIOUS-BINARY');
  await assert.rejects(generateAlphaUninstallInventory(f.dir),/unsafe Alpha/);
  const b=await readFile(join(f.dir,'SHA256SUMS.txt'),'utf8');
  await writeFile(join(f.dir,'SHA256SUMS.txt'),b.replace(/^[a-f0-9]{64}/,'0'.repeat(64)));
  await assert.rejects(generateAlphaUninstallInventory(f.dir),/unsafe Alpha/);
 }finally{await f.close();}
});
test('symlinks cannot add arbitrary filesystem paths to installer cleanup',async()=>{
 const f=await fixture();
 try{
  const target=join(f.dir,'outside-test.txt');
  await writeFile(target,'OUTSIDE-BUILD');
  await symlink(target,join(f.dir,'bin','untrusted.txt'));
  await assert.rejects(generateAlphaUninstallInventory(f.dir),/unsafe Alpha/);
 }finally{await f.close();}
});
