// Offline operator: create a kit in a private existing directory.
import {open,lstat,realpath} from 'node:fs/promises';
import {constants} from 'node:fs';
import {resolve,join} from 'node:path';
import {createNativeSessionKit} from '../lib/quantic/native-session-kit.mjs';
const check=x=>{if(!x)throw Error('Session kit preparation refused');};
let key,kit;
try{
 const [dir]=process.argv.slice(2);
 check(process.platform==='linux'&&process.argv.length===3&&resolve(dir)===dir&&await realpath(dir)===dir);
 const st=await lstat(dir);check(st.isDirectory()&&st.uid===process.getuid()&&(st.mode&0o077)===0);
 async function read(name,max){
  check(/^[a-z0-9.-]+$/.test(name)&&name!=='.'&&name!=='..');
  const fd=await open(join(dir,name),constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
  try{
   const s=await fd.stat();check(s.isFile()&&s.uid===process.getuid()&&s.nlink===1&&(s.mode&0o077)===0&&s.size>0&&s.size<=max);
   const raw=Buffer.alloc(s.size+1);let n=0;
   while(n<raw.length){const r=await fd.read(raw,n,raw.length-n,null);if(!r.bytesRead)break;n+=r.bytesRead;}
   check(n===s.size);return raw.subarray(0,n);
  }finally{await fd.close();}
 }
 const cfg=JSON.parse((await read('configuration.json',65536)).toString('utf8'));
 for(const k of ['ca','cert','key'])check(typeof cfg.tlsFiles?.[k]==='string'&&/^peer-[a-z0-9-]{1,48}\.pem$/.test(cfg.tlsFiles[k]));
 const ca=await read(cfg.tlsFiles.ca,32768),cert=await read(cfg.tlsFiles.cert,32768);
 key=await read(cfg.tlsFiles.key,32768);
 kit=createNativeSessionKit({configuration:cfg,tls:{ca,cert,key},labOnly:true});
 const fd=await open(join(dir,'session-kit.json'),'wx',0o600);
 try{await fd.writeFile(kit.bytes);await fd.sync();}finally{await fd.close();}
 const parent=await open(dir,'r');try{await parent.sync();}finally{await parent.close();}
 process.stdout.write(JSON.stringify({status:'session-kit-created-lab',kitSha256:kit.kitSha256,configurationSha256:kit.configurationSha256})+'\n');
}catch{process.stderr.write('Session kit preparation refused. No overwrite or account activation.\n');process.exitCode=1;}
finally{key?.fill(0);kit?.bytes.fill(0);}
