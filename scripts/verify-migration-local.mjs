// Offline read-only archive verification. No login, key export, registry or migration writes.
import {open,lstat} from 'node:fs/promises';
import {isAbsolute,extname} from 'node:path';
import {createInterface} from 'node:readline/promises';
import {Writable} from 'node:stream';
import {verifyMigrationArchiveOffline} from '../lib/quantic/migration-proof-node.mjs';
const MAX=23*1024*1024;
const check=v=>{if(!v)throw Error('Verification refused');};
async function archiveText(path){
 check(isAbsolute(path)&&extname(path).toLowerCase()==='.qma');
 const before=await lstat(path);check(before.isFile()&&!before.isSymbolicLink()&&before.size>0&&before.size<=MAX);
 const f=await open(path,'r');
 try{
  const st=await f.stat();check(st.isFile()&&st.size===before.size&&st.size<=MAX);
  const bytes=Buffer.alloc(st.size+1);let n=0;
  try{
   while(n<bytes.length){const x=await f.read(bytes,n,bytes.length-n,null);if(x.bytesRead===0)break;n+=x.bytesRead;}
   check(n===st.size);return new TextDecoder('utf-8',{fatal:true}).decode(bytes.subarray(0,n));
  }finally{bytes.fill(0);}
 }finally{await f.close();}
}
async function readPassword(){
 check(process.stdin.isTTY&&process.stderr.isTTY);
 const muted=new Writable({write(_chunk,_encoding,callback){callback();}});
 const rl=createInterface({input:process.stdin,output:muted,terminal:true,historySize:0});
 try{
  process.stderr.write('Phrase secrete de l archive (non affichee) : ');
  const password=await rl.question('');
  check(password.length>=14&&password.length<=1024);
  return password;
 }finally{rl.close();muted.end();process.stderr.write('\n');}
}
try{
 const [path,expectedAddress,trustedRootPin]=process.argv.slice(2);
 check(process.argv.length===5&&/^[a-z0-9][a-z0-9._-]{2,31}~(?:[a-f0-9]{10}|[a-f0-9]{32})@quantic$/.test(expectedAddress)&&/^[a-f0-9]{64}$/.test(trustedRootPin));
 const text=await archiveText(path);
 let password=await readPassword();
 try{
  const result=await verifyMigrationArchiveOffline(text,password,{expectedAddress,trustedRootPin});
  process.stdout.write(JSON.stringify(result,null,2)+'\n');
  process.stderr.write('Verification historique uniquement. Aucune restauration ni suppression autorisee.\n');
 }finally{password='';}
}catch{process.stderr.write('Verification refusee ou interrompue. Archive et compte d origine inchanges.\n');process.exitCode=1;}
