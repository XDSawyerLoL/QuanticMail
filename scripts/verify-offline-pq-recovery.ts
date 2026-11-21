// Run explicitly from a trusted terminal with Node 24; no web/renderer entry point.
import {open,constants} from "node:fs/promises";
import {isAbsolute} from "node:path";
import {createInterface} from "node:readline";
import {Writable} from "node:stream";
import {ARCHIVE_MAX_BYTES} from "../lib/quantic/migration-archive.ts";
import {verifyOfflinePqRecovery} from "../desktop/offline-pq-recovery.ts";
async function readLocal(path:string,limit:number){
 if(!isAbsolute(path))throw Error("absolute path required");
 const f=await open(path,constants.O_RDONLY|constants.O_NONBLOCK|constants.O_NOFOLLOW);
 try{
  const s=await f.stat();if(!s.isFile()||s.size>limit||s.uid!==process.getuid?.()||(s.mode&0o077)!==0)throw Error("private regular file required");
  const b=Buffer.alloc(limit+1);let n=0;
  while(n<b.length){const r=await f.read(b,n,b.length-n,null);if(!r.bytesRead)break;n+=r.bytesRead;}
  if(n>limit)throw Error("file too large");
  return new TextDecoder("utf-8",{fatal:true}).decode(b.subarray(0,n));
 }finally{await f.close();}
}
async function password(){
 const sink=new Writable({write(_chunk,_encoding,done){done();}});
 const rl=createInterface({input:process.stdin,output:sink,terminal:true});
 try{
  process.stderr.write("Phrase secrète de l’archive (saisie masquée) : ");
  return await new Promise<string>((resolve,reject)=>{
   rl.once("SIGINT",()=>reject(Error("cancelled")));
   rl.once("close",()=>reject(Error("cancelled")));
   rl.question("",resolve);
  });
 }finally{rl.close();process.stderr.write("\n");}
}
try{
 const [archive,pins,fixture]=process.argv.slice(2);
 if(process.platform!=="linux"||!process.stdin.isTTY||!process.stderr.isTTY||!archive||!pins||process.argv.length>5)throw Error("Linux trusted terminal required");
 const config=JSON.parse(await readLocal(pins,16384));
 const historical=fixture?JSON.parse(await readLocal(fixture,2*1024*1024)):undefined;
 const text=await readLocal(archive,Math.ceil((ARCHIVE_MAX_BYTES+16)/3)*4+512);
 const result=await verifyOfflinePqRecovery(text,await password(),config,historical);
 process.stdout.write(JSON.stringify(result)+"\n");
}catch{
 process.stderr.write("Vérification refusée ou indisponible. Aucune donnée restaurée ni supprimée.\n");
 process.exitCode=1;
}
