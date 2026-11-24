// Generate exact, verified nonrecursive uninstall inventory from finalized package.
import { readdir, lstat, readFile, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { createHash } from 'node:crypto';
const [root, list, checks] = process.argv.slice(2).map(resolveArg);
function resolveArg(x){return resolve(x)}
const requireSafe = ok => { if (!ok) throw Error('Unsafe Sentinel package inventory'); };
const hash = b => createHash('sha256').update(b).digest('hex');
const safe = n => /^[A-Za-z0-9_ .+-]{1,150}$/.test(n) && n !== '.' && n !== '..' && !/[. ]$/.test(n);
const files = new Map(), dirs = [];
async function scan(dir, rel=''){
 for(const entry of await readdir(dir,{withFileTypes:true})){
  requireSafe(safe(entry.name));
  const path=join(dir,entry.name), name=rel+entry.name, st=await lstat(path);
  requireSafe(!st.isSymbolicLink());
  if(st.isDirectory()){dirs.push(name);await scan(path,name+'/');}
  else{requireSafe(st.isFile()&&st.nlink===1&&st.size>0&&st.size<=128*1024*1024);files.set(name,hash(await readFile(path)));}
 }
}
await scan(root);
requireSafe(files.has('QuanticSentinel.exe')&&files.has('IdentityVault.exe')&&files.has('SHA256SUMS.txt'));
const manifest=await readFile(join(root,'SHA256SUMS.txt'),'utf8');
const seen=new Set();
for(const line of manifest.trimEnd().split(/\r?\n/)){
 const m=/^([a-f0-9]{64}) \*\.\/(.+)$/.exec(line);
 requireSafe(m&&m[2]!=='SHA256SUMS.txt'&&!seen.has(m[2])&&files.get(m[2])===m[1]);
 seen.add(m[2]);
}
requireSafe(seen.size===files.size-1);
const win = n => n.replaceAll('/','\\');
const ordered=dirs.sort((a,b)=>b.split('/').length-a.split('/').length||a.localeCompare(b));
const unlink=[...files.keys()].sort().map(n=>' Delete "$INSTDIR\\'+win(n)+'"');
for(const d of ordered)unlink.push(' RMDir "$INSTDIR\\'+win(d)+'"');
const guard=[];
for(const d of ordered){
 // Missing directories are allowed on a retry after a partial uninstall.
 guard.push(" System::Call 'kernel32::GetFileAttributesW(w \"$INSTDIR\\"+win(d)+"\") i .r0'",
  ' IntCmp $0 -1 +3 0 0',' IntOp $1 $0 & 0x410',' IntCmp $1 0x10 +1 refused refused');
}
await writeFile(list,unlink.join('\n')+'\n',{flag:'wx'});
await writeFile(checks,guard.join('\n')+'\n',{flag:'wx'});
