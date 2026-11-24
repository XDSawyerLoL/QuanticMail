// Dedicated native mailbox adapter. No legacy handler, browser routes,
 // federation, discovery, generic registration or public HTTP listener.
import {createServer} from 'node:http';
import {realpath,lstat,open,unlink} from 'node:fs/promises';
import {join,isAbsolute} from 'node:path';
import {RelayRuntime} from './runtime.ts';
import {createFileRelayStateStore} from './storage.ts';
import {nativeMailboxOperation} from '../lib/quantic/native-mailbox-http.mjs';
import {publishNativeEnrollment,exportNativeAuthoritySnapshot} from './native-enrollment-publication.mjs';
const check=x=>{if(!x)throw Error('Native mailbox-only laboratory refused');};
export async function startNativeMailboxOnly({dataDir,port=0,peerSource,enrollment}){
 check(process.platform==='linux'&&typeof dataDir==='string'&&isAbsolute(dataDir)&&await realpath(dataDir)===dataDir&&typeof peerSource==='function'&&Number.isInteger(port)&&port>=0&&port<=65535);
 const st=await lstat(dataDir);check(st.isDirectory()&&st.uid===process.getuid()&&!(st.mode&0o077));
 const lock=join(dataDir,'.native-mailbox-only.lock'),fd=await open(lock,'wx',0o600);
 try{await fd.writeFile(String(process.pid));await fd.sync();}finally{await fd.close();}
 const dir=await open(dataDir,'r');try{await dir.sync();}finally{await dir.close();}
 let server,runtime,closed=false;
 const release=async()=>{await unlink(lock);const d=await open(dataDir,'r');try{await d.sync();}finally{await d.close();}};
 try{
  runtime=new RelayRuntime(createFileRelayStateStore(dataDir));await runtime.initialize();
  const publication=enrollment?await publishNativeEnrollment(runtime,enrollment):null;
  server=createServer(async(req,res)=>{
   const reply=(status,value)=>{if(!res.destroyed&&!res.writableEnded){const b=Buffer.from(JSON.stringify(value));res.writeHead(status,{'Content-Type':'application/json','Content-Length':b.length,'Cache-Control':'no-store','Connection':'close'});res.end(b);}};
   const match=/^\/api\/quantic\/native\/v1\/(send|pull|ack|recover)$/.exec(req.url??'');
   if(!match){req.resume();reply(404,{error:'Native route only'});return;}
   const len=Number(req.headers['content-length']),auth=req.headers.authorization;
   if(req.socket.remoteAddress!=='127.0.0.1'||req.method!=='POST'||req.headers.origin!==undefined||req.headers['sec-fetch-site']!==undefined||
    req.headers['transfer-encoding']!==undefined||req.headers['content-type']!=='application/json'||!Number.isInteger(len)||len<1||len>32768||
    typeof auth!=='string'||!/^Bearer [A-Za-z0-9_-]{43}$/.test(auth)){req.resume();reply(403,{error:'Native operation refused'});return;}
   try{const chunks=[];let n=0;for await(const b of req){n+=b.length;check(n<=len);chunks.push(b);}
    check(n===len);
    const value=await nativeMailboxOperation(runtime,peerSource,match[1],JSON.parse(Buffer.concat(chunks).toString('utf8')),auth.slice(7),{nativeOnly:true});
    reply(match[1]==='send'?202:200,value);
   }catch{reply(403,{error:'Native operation refused'});}
  });
  server.requestTimeout=10000;server.headersTimeout=5000;server.maxConnections=16;
  await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(port,'127.0.0.1',resolve);});
  return {port:server.address().port,publication,exportAuthoritySnapshot:()=>exportNativeAuthoritySnapshot(runtime),
   async close(){if(closed)return;closed=true;await new Promise((resolve,reject)=>{server.close(e=>e?reject(e):resolve());server.closeAllConnections();});await runtime.flush();await release();}};
 }catch(e){if(server?.listening)await new Promise(r=>server.close(r));await release();throw e;}
}
