// Laboratory-only private witness file loader. Prevents trivial symlink,
// hardlink and permission-based key substitution, but NOT compromise of the
// owning OS account, root, memory, filesystem, or a real HSM boundary.
import {constants,openSync,closeSync,fstatSync,lstatSync,readFileSync,realpathSync} from 'node:fs';
import {dirname,isAbsolute} from 'node:path';
import {createPrivateKey} from 'node:crypto';

const refuse=()=>{throw Error('Private witness file refused');};
export function readWitnessPrivateFileLab(path,{maxBytes=524288}={}){
 if(typeof path!=='string'||!isAbsolute(path)||!Number.isSafeInteger(maxBytes)
   ||maxBytes<1||maxBytes>524288)refuse();
 const dir=dirname(path);
 // A private immediate parent prevents replacement by a different local
 // user even under a shared world-writable ancestor such as /tmp.
 if(realpathSync(dir)!==dir)refuse();
 if(process.platform!=='win32'){
  const ds=lstatSync(dir);
  if(!ds.isDirectory()||ds.uid!==process.getuid()||(ds.mode&0o077)!==0)refuse();
 }
 const flags=constants.O_RDONLY|(process.platform==='win32'?0:constants.O_NOFOLLOW);
 const fd=openSync(path,flags);
 try{
  const s=fstatSync(fd),l=lstatSync(path);
  if(!s.isFile()||!l.isFile()||s.dev!==l.dev||s.ino!==l.ino
    ||s.nlink!==1||l.nlink!==1||s.size<1||s.size>maxBytes)refuse();
  if(process.platform!=='win32'&&(s.uid!==process.getuid()||(s.mode&0o077)!==0))refuse();
  const bytes=readFileSync(fd);
  const after=fstatSync(fd);
  if(bytes.length!==s.size||after.dev!==s.dev||after.ino!==s.ino
    ||after.size!==s.size||after.mtimeMs!==s.mtimeMs) {
   bytes.fill(0);refuse();
  }
  return bytes;
 }finally{closeSync(fd);}
}
export function loadWitnessPrivateKeyLab(path){
 const bytes=readWitnessPrivateFileLab(path,{maxBytes:65536});
 try{return createPrivateKey(bytes);}finally{bytes.fill(0);}
}
