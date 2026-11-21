// Explicit two-host lab, fixed native mailbox routes only; no public HTTP endpoint.
// Native pacer and native sink are independently operated, not children of this process.
import {createHash,hkdfSync} from 'node:crypto';
import {lstat,realpath,readdir,open} from 'node:fs/promises';
import {isAbsolute,join} from 'node:path';
import {createSocket} from 'node:dgram';
import {createServer,request} from 'node:http';
import {cellKey} from '../labs/quantic-native/scattering/scattering-cell.mjs';
import {reliableCellStream} from '../labs/quantic-native/scattering/scattering-reliable-lab.mjs';
const MAX=32768,FRAME=65536,OPS=16;
const profiles=Object.freeze({mailbox:Object.freeze({base:'/api/quantic/native/v1/',ops:Object.freeze(['send','pull','ack','recover'])}), 'pay-lab':Object.freeze({base:'/api/quantic/pay-lab/v1/',ops:Object.freeze(['checkpoint','submit'])}), 'pay-round-lab':Object.freeze({base:'/api/quantic/pay-round-lab/v1/',ops:Object.freeze(['status','prepare','change-view','commit','learn','upload-begin','upload-chunk','upload-finish'])}), 'pay-replica-lab':Object.freeze({base:'/api/quantic/pay-replica-lab/v1/',ops:Object.freeze(['status','admit','prepare','change-view','commit','learn','upload-begin','upload-chunk','upload-finish','record-begin','record-chunk'])})});
const check=x=>{if(!x)throw Error('Scattering mailbox lab refused');};
const port=(v,zero=false)=>Number.isInteger(v)&&v>=(zero?0:1)&&v<=65535;
const tokenOK=v=>typeof v==='string'&&/^[A-Za-z0-9._~-]{40,256}$/.test(v);
const exact=(v,ks)=>v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).length===ks.length&&ks.every(k=>Object.hasOwn(v,k));
function decode(s,min=0){
 check(typeof s==='string'&&s.length<=Math.ceil(MAX/3)*4&&/^[A-Za-z0-9_-]*$/.test(s));
 const b=Buffer.from(s,'base64url');check(b.length>=min&&b.length<=MAX&&b.toString('base64url')===s);return b;
}
async function privateDirectory(p){
 check(process.platform==='linux'&&typeof p==='string'&&isAbsolute(p)&&await realpath(p)===p);
 const s=await lstat(p);check(s.isDirectory()&&s.uid===process.getuid()&&(s.mode&0o077)===0);
}
async function reserve(c){
 await privateDirectory(c.queueDir);await privateDirectory(c.stateDir);check(c.queueDir!==c.stateDir&&!(await readdir(c.queueDir)).length);
 // A consumed marker is never removed, including when startup fails. Local rollback
 // or cloning of the directory is not prevented; independent provisioning required.
 const name='used-'+createHash('sha256').update(Buffer.from(c.epochHex,'hex')).digest('hex');
 const f=await open(join(c.stateDir,name),'wx',0o600);
 try{await f.writeFile('epoch consumed\n');await f.sync();}finally{await f.close();}
 const dir=await open(c.stateDir,'r');try{await dir.sync();}finally{await dir.close();}
}
async function readBounded(s){
 const chunks=[];let n=0;for await(const b of s){n+=b.length;check(n<=MAX);chunks.push(b);}return Buffer.concat(chunks,n);
}
function response(res,status,body){
 if(res.destroyed)return;
 res.writeHead(status,{'Content-Type':'application/json','Content-Length':body.length,'Cache-Control':'no-store',Connection:'close'});res.end(body);
}
const errorBody=Buffer.from('{"error":"native mailbox operation not confirmed"}');
export async function startScatteringMailboxEndpoint(c,{windowsBootstrap,profile='mailbox'}={}){
 check(Object.hasOwn(profiles,profile));
 const BASE=profiles[profile].base,allowed=new Set(profiles[profile].ops);
 check(c?.labOnly===true&&['client','relay'].includes(c.role)&&/^[a-f0-9]{64}$/.test(c.secretHex)&&/^[a-f0-9]{64}$/.test(c.epochHex)&&!/^0+$/.test(c.secretHex)&&!/^0+$/.test(c.epochHex)&&c.secretHex!==c.epochHex&&port(c.recvPort,true)&&port(c.httpPort,c.role==='client'));
 let guard;
 if(process.platform==='win32'){
  if(!windowsBootstrap)throw Error('explicit Windows native guard required');
  const {reserveWindowsScattering}=await import('../desktop/native-windows-scattering.mjs');
  guard=await reserveWindowsScattering(c,windowsBootstrap);
 }else{await reserve(c);}
 const secret=Buffer.from(c.secretHex,'hex'),epoch=Buffer.from(c.epochHex,'hex');
 const domainSecret=profile==='mailbox'?secret:Buffer.from(hkdfSync('sha256',secret,epoch,Buffer.from('quantic-'+profile+'-scattering/v1'),32));
 const ab=cellKey(domainSecret,epoch,'a-b'),ba=cellKey(domainSecret,epoch,'b-a');domainSecret.fill(0);secret.fill(0);epoch.fill(0);
 let cells,server,stopped=false,upstream,pending,busy=false,next=1,input=Buffer.alloc(0),relayResponse,waitingNext=false;
 const udp=createSocket('udp4');
 let resolveClosed;const closed=new Promise(resolve=>{resolveClosed=resolve;});
 function stop(){
  if(stopped)return;stopped=true;
  if(pending){clearTimeout(pending.timer);pending.reject(Error('Scattering epoch terminated'));pending=null;}
  upstream?.destroy();cells?.stream.destroy();input.fill(0);
  server?.closeAllConnections();server?.close();try{udp.close();}catch{}
  guard?.close();resolveClosed();
 }
 if(guard)void guard.closed.then(stop);
 async function sendFrame(frame){
  const raw=Buffer.from(JSON.stringify(frame));check(raw.length>0&&raw.length<=FRAME);
  const h=Buffer.alloc(4);h.writeUInt32BE(raw.length);const bytes=Buffer.concat([h,raw]);
  try{for(let o=0;o<bytes.length;o+=8192){check(!stopped);await new Promise((resolve,reject)=>cells.stream.write(bytes.subarray(o,o+8192),e=>e?reject(e):resolve()));}}
  finally{raw.fill(0);bytes.fill(0);}
 }
 function forward(frame,body){
  return new Promise((resolve,reject)=>{
   const req=request({hostname:'127.0.0.1',port:c.httpPort,path:BASE+frame.op,method:'POST',agent:false,headers:{'Content-Type':'application/json','Content-Length':body.length,Authorization:'Bearer '+frame.token,Connection:'close'}},async res=>{
    try{const data=await readBounded(res);check(Number.isInteger(res.statusCode)&&res.statusCode>=200&&res.statusCode<=599);resolve({status:res.statusCode,body:data});}
    catch(e){res.destroy();reject(e);}
   });
   upstream=req;const timer=setTimeout(()=>req.destroy(Error('relay timeout')),10000);
   req.on('close',()=>{clearTimeout(timer);if(upstream===req)upstream=undefined;});req.on('error',reject);req.end(body);
  });
 }
 async function onFrame(frame){
  if(c.role==='relay'){
   check(!stopped&&exact(frame,['kind','seq','op','token','body'])&&frame.kind==='request'&&frame.seq===next&&next<=OPS&&allowed.has(frame.op)&&tokenOK(frame.token));
   // The client receives a full response slightly before our last carrier ACK.
   // Accept at most one next sequential request while that ACK is outstanding.
   // Never execute parallel upstream operations or buffer unbounded requests.
   if(busy){
    check(relayResponse&&!waitingNext);
    waitingNext=true;
    try{await relayResponse;}finally{waitingNext=false;}
    check(!stopped&&!busy&&frame.seq===next);
   }
   const data=decode(frame.body,1);busy=true;next++;
   try{
    let result;try{result=await forward(frame,data);}catch{result={status:502,body:errorBody};}
    // The upstream response, not a volatile carrier ACK, is returned to the client.
    relayResponse=sendFrame({kind:'response',seq:frame.seq,status:result.status,body:result.body.toString('base64url')});
    await relayResponse;
   }finally{data.fill(0);relayResponse=undefined;busy=false;}
  }else{
   check(pending&&exact(frame,['kind','seq','status','body'])&&frame.kind==='response'&&frame.seq===pending.seq&&Number.isInteger(frame.status)&&frame.status>=200&&frame.status<=599);
   const body=decode(frame.body);const p=pending;pending=null;clearTimeout(p.timer);p.resolve({status:frame.status,body});
  }
 }
 function consume(chunk){
  try{
   check(input.length+chunk.length<=FRAME+4+128);input=Buffer.concat([input,chunk]);
   while(input.length>=4){
    const n=input.readUInt32BE(0);check(n>=1&&n<=FRAME);if(input.length<n+4)return;
    const frame=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(input.subarray(4,n+4)));
    input=input.subarray(n+4);void onFrame(frame).catch(stop);
   }
  }catch{stop();}
 }
 async function handle(req,res){
  const op=typeof req.url==='string'&&req.url.startsWith(BASE)?req.url.slice(BASE.length):'';
  const auth=req.headers.authorization;
  const len=Number(req.headers['content-length']);
  if(req.method!=='POST'||!allowed.has(op)||typeof auth!=='string'||!auth.startsWith('Bearer ')||!tokenOK(auth.slice(7))||req.headers.origin!==undefined||req.headers['transfer-encoding']!==undefined||req.headers['content-type']!=='application/json'||!Number.isInteger(len)||len<1||len>MAX){response(res,400,errorBody);req.resume();return;}
  if(stopped||busy||next>OPS){response(res,503,errorBody);req.resume();return;}
  busy=true;let transmitted=false,data;
  try{
   data=await readBounded(req);check(data.length===len);
   const seq=next++;
   transmitted=true;
   const reply=new Promise((resolve,reject)=>{pending={seq,resolve,reject,timer:setTimeout(stop,18000)};});
   const [,result]=await Promise.all([sendFrame({kind:'request',seq,op,token:auth.slice(7),body:data.toString('base64url')}),reply]);
   response(res,result.status,result.body);
  }catch{if(transmitted)stop();response(res,502,errorBody);}
  finally{data?.fill(0);busy=false;}
 }
 try{
  await new Promise((resolve,reject)=>{udp.once('error',reject);udp.bind(c.recvPort,'127.0.0.1',()=>{udp.removeListener('error',reject);resolve();});});
  udp.on('error',stop);
  cells=reliableCellStream({sendKey:c.role==='client'?ab:ba,recvKey:c.role==='client'?ba:ab,dir:c.queueDir,compactPacing:true,dualProofPacing:true});
  cells.stream.on('error',stop);cells.stream.on('close',stop);cells.stream.on('data',consume);
  udp.on('message',m=>cells.receive(m));
  if(c.role==='client'){
   server=createServer((req,res)=>{void handle(req,res).catch(stop);});
   server.maxConnections=8;server.requestTimeout=10000;server.headersTimeout=5000;server.setTimeout(20000,s=>s.destroy());
   await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(c.httpPort,'127.0.0.1',()=>{server.removeListener('error',reject);resolve();});});
   server.on('error',stop);
  }
  check(!stopped);
  return Object.freeze({recvPort:udp.address().port,httpPort:server?.address().port,closed,close:stop});
 }catch(e){stop();throw e;}finally{ab.fill(0);ba.fill(0);}
}
