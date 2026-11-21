// Explicit laboratory HTTPS authority. Not part of the mail relay.
import {createServer} from 'node:https';
import {createHash} from 'node:crypto';
import {issueCheckpoint} from '../lib/quantic/native-checkpoint-authority.mjs';
const hash=b=>createHash('sha256').update(b).digest('hex');
const check=(x)=>{if(!x)throw Error('authority refused');};
export async function startNativeCheckpointAuthority({tls,privateKey,load,clientPins,port=0}){
 check(Number.isInteger(port)&&port>=0&&port<=65535&&typeof load==='function');
 check(Array.isArray(clientPins)&&clientPins.length>=1&&clientPins.length<=32&&clientPins.every(p=>typeof p==='string'&&/^[a-f0-9]{64}$/.test(p)));
 const allowed=new Set(clientPins),budgets=new Map();let running=0;
 const server=createServer({...tls,minVersion:'TLSv1.3',requestCert:true,rejectUnauthorized:true},async(req,res)=>{
  const reply=(status,value)=>{
   if(res.destroyed||res.writableEnded)return;
   const body=Buffer.from(JSON.stringify(value));
   res.writeHead(status,{'Content-Type':'application/json','Content-Length':body.length,'Cache-Control':'no-store','Connection':'close'});res.end(body);
  };
  let entered=false;
  try{
   const cert=req.socket.getPeerCertificate();
   check(req.socket.authorized&&cert?.raw&&allowed.has(hash(cert.raw)));
   check(req.method==='POST'&&req.url==='/native-checkpoint'&&req.headers['content-type']==='application/json'&&!req.headers['transfer-encoding']);
   const length=Number(req.headers['content-length']);check(Number.isInteger(length)&&length>=1&&length<=4096);
   const id=hash(cert.raw),now=Date.now();let b=budgets.get(id);
   if(!b||now>=b.until)b={count:0,until:now+60000};
   check(b.count<120&&running<8);b.count++;budgets.set(id,b);running++;entered=true;
   let n=0;const chunks=[];
   for await(const c of req){n+=c.length;check(n<=length);chunks.push(c);}
   check(n===length);
   const request=JSON.parse(Buffer.concat(chunks).toString('utf8'));
   const {state,policy}=await load();
   const result=issueCheckpoint({state,policy,request,privateKey});
   check(Buffer.byteLength(JSON.stringify(result))<=131072);
   reply(200,result);
  }catch{reply(403,{error:'authority refused'});}
  finally{if(entered)running--;}
 });
 server.requestTimeout=5000;server.headersTimeout=3000;server.keepAliveTimeout=1000;server.maxRequestsPerSocket=1;server.maxConnections=32;
 await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(port,'127.0.0.1',resolve);});
 return {port:server.address().port,close:()=>new Promise((resolve,reject)=>{server.close(e=>e?reject(e):resolve());server.closeAllConnections();})};
}
