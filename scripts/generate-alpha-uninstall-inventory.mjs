// Generate exact NSIS unlink list from the finalized, hashed Windows package.
// Never use RMDir /r. Unknown files and separately held vault data are retained.
// Source files are included exclusively by the staged package's SHA256SUMS.txt.
// The generated .nsh is a build-only input, NEVER executed as PowerShell.
import {readdir,lstat,readFile,writeFile} from 'node:fs/promises';
import {join,resolve,dirname} from 'node:path';
import {pathToFileURL} from 'node:url';
import {createHash} from 'node:crypto';
const die=x=>{if(!x)throw Error('Refused unsafe Alpha installer uninstall inventory');};
const digest=b=>createHash('sha256').update(b).digest('hex');
const safeName=n=>typeof n==='string'&&n.length>=1&&n.length<=180
 &&n!=='.'&&n!=='..'&&!/[\x00-\x1f\x7f"\\$]/.test(n)&&!/[. ]$/.test(n);
const safeRelative=r=>typeof r==='string'&&r.length<250&&r.split('/').every(safeName)
 &&!r.startsWith('/')&&!r.includes('\\');
const windows=r=>r.split('/').join('\\');
const sort=(a,b)=>a<b?-1:a>b?1:0;
export async function generateAlphaUninstallInventory(dir){
 const st=await lstat(dir);
 die(st.isDirectory()&&!st.isSymbolicLink());
 const manifest=await readFile(join(dir,'SHA256SUMS.txt'),'utf8');
 die(manifest.length>1&&manifest.length<=262144&&manifest.endsWith('\n'));
 const entries=new Map();
 for(const line of manifest.slice(0,-1).split('\n')){
  const m=/^([a-f0-9]{64}) \*\.\/(.+)$/.exec(line);
  die(m&&safeRelative(m[2])&&m[2]!=='SHA256SUMS.txt'&&!entries.has(m[2]));
  entries.set(m[2],m[1]);
 }
 die(entries.size>=12&&entries.size<=3000);
 const files=new Set(),directories=new Set();
 async function walk(current){
  for(const d of await readdir(join(dir,current),{withFileTypes:true})){
   die(safeName(d.name));
   const rel=(current?current+'/':'')+d.name;
   die(safeRelative(rel));
   const full=join(dir,...rel.split('/')),st=await lstat(full);
   die(!st.isSymbolicLink());
   if(st.isDirectory()){
    die(d.isDirectory());
    directories.add(rel);
    await walk(rel);
   }else{
    die(d.isFile()&&st.isFile()&&st.nlink===1&&st.size>0&&st.size<=256*1024*1024);
    files.add(rel);
    if(rel!=='SHA256SUMS.txt'){
     die(entries.has(rel));
     const b=await readFile(full);
     die(b.length===st.size&&digest(b)===entries.get(rel));
    }
   }
  }
 }
 await walk('');
 die(files.has('SHA256SUMS.txt')&&files.size===entries.size+1);
 for(const name of entries.keys())die(files.has(name));
 const ordered=[...files].sort(sort);
 const dirs=[...directories].sort((a,b)=>b.split('/').length-a.split('/').length||sort(b,a));
 // Exact quoted paths; never recurse, never follow extra directories.
 return ['; Generated strictly from verified, complete SHA256SUMS inventory.',
  '; No recursive deletes. Unknown user files force the parent RMDir to fail.',
  ...ordered.map(p=>' Delete "$INSTDIR\\app\\'+windows(p)+'"'),
  ...dirs.map(p=>' RMDir "$INSTDIR\\app\\'+windows(p)+'"'),
  ''].join('\n');
}
if(process.argv[1]&&pathToFileURL(resolve(process.argv[1])).href===import.meta.url){
 const [dir,out]=process.argv.slice(2);
 die(process.argv.length===4&&typeof dir==='string'&&typeof out==='string'
  &&resolve(dir)!==resolve(out)&&dirname(resolve(out))!==resolve(dir));
 const inventory=await generateAlphaUninstallInventory(dir);
 await writeFile(out,inventory,{flag:'wx',mode:0o600});
 process.stdout.write('Alpha uninstall inventory generated without recursive deletion.\n');
}
