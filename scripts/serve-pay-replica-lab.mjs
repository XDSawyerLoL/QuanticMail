// One separately provisioned fictional Pay witness, local carrier ingress only.
// Run one instance per laboratory machine with a different key and database.
import {createServer} from 'node:http';
import {createPrivateKey,timingSafeEqual} from 'node:crypto';
import {lstatSync,realpathSync,openSync,readFileSync,closeSync,fstatSync,constants} from 'node:fs';
import {isAbsolute} from 'node:path';
import {openPayRoundReplica} from '../lib/quantic/pay-round-replica.mjs';
import {createRoundUpload,createRoundDownload} from '../lib/quantic/pay-round-transfer.mjs';
import {createRoundCirculationLab} from '../lib/quantic/pay-circulation-lab.mjs';
const check=v=>{if(!v)throw Error('Pay witness refused');};
function privateRead(path,max){
 check(typeof path==='string'&&isAbsolute(path)&&realpathSync(path)===path);
 const s=lstatSync(path);check(s.isFile()&&s.uid===process.getuid()&&s.nlink===1&&(s.mode&0o077)===0&&s.size>0&&s.size<=max);
 const fd=openSync(path,constants.O_RDONLY|constants.O_NOFOLLOW);
 try{const a=fstatSync(fd);check(a.ino===s.ino&&a.dev===s.dev&&a.size===s.size);const b=readFileSync(fd);check(b.length===s.size);return b;}
 finally{closeSync(fd)}
}
const exact=(o,k)=>o&&typeof o==='object'&&!Array.isArray(o)&&Object.keys(o).length===k.length&&k.every(x=>Object.hasOwn(o,x));
async function main(){
 check(process.platform==='linux'&&process.argv.length===4&&['provision','serve'].includes(process.argv[2]));
 const raw=privateRead(process.argv[3],131072);let c;
 try{c=JSON.parse(raw.toString('utf8'));}finally{raw.fill(0);}
 check(exact(c,['simulationOnly','directory','chainConfig','expectedNetwork','authorityKeyFile','authorityPin','authorityPQKeyFile','authorityPQPin','token','port'])&&c.simulationOnly===true&&Number.isInteger(c.port)&&c.port>=1&&c.port<=65535&&typeof c.token==='string'&&/^[a-f0-9]{64}$/.test(c.token));
 // Verify the provisioned signed proposals, prior certificates, balance and
 // domain locally. The HTTP requester cannot supply an alternative config.
 const chain=createRoundCirculationLab(c.chainConfig);
 const network=chain.snapshot([]).network;
 check(network===c.expectedNetwork&&c.chainConfig.witnesses.some(a=>a.pin===c.authorityPin&&a.pqPin===c.authorityPQPin));
 const secret=privateRead(c.authorityKeyFile,8192);
 let key;try{key=createPrivateKey(secret);}finally{secret.fill(0);}
 const pqSecret=privateRead(c.authorityPQKeyFile,16384);
 let pqKey;try{pqKey=createPrivateKey(pqSecret);}finally{pqSecret.fill(0);}
 const options={directory:c.directory,config:c.chainConfig,classicalPrivateKey:key,pqPrivateKey:pqKey,authorityPin:c.authorityPin};
 const store=openPayRoundReplica({...options,createNew:process.argv[2]==='provision'});
 if(process.argv[2]==='provision'){store.close();console.log('PROVISIONED PAY REPLICA LAB');return;}
 const auth=Buffer.from('Bearer '+c.token);delete c.token;
 let busy=false;
 const upload=createRoundUpload({validate:payload=>check(exact(payload,['op','input'])&&['prepare','learn','admit'].includes(payload.op))});
 const download=createRoundDownload({readRecord:height=>store.record(height)});
 function dispatch(op,input){
  if(op==='status'){check(input===null);return store.status();}
  if(op==='admissionReport'){check(input===null);return store.admissionReport();}
  if(op==='voteAdmission')return store.voteAdmission(input);
  if(op==='admit')return store.admit(input);
  if(op==='prepare')return store.prepare(input);
  if(op==='changeView')return store.changeView(input);
  if(op==='commit')return store.commitVote(input);
  if(op==='learn')return store.learn(input);
  throw Error('Operation refused');
 }
 const server=createServer(async(req,res)=>{
  const send=(status,data)=>{const b=Buffer.from(JSON.stringify(data));res.writeHead(status,{'Content-Type':'application/json','Content-Length':b.length,'Cache-Control':'no-store',Connection:'close'});res.end(b);};
  const header=Buffer.from(req.headers.authorization??'');
  if(header.length!==auth.length||!timingSafeEqual(header,auth)){req.resume();send(401,{});return;}
  if(busy){req.resume();send(503,{});return;}
  busy=true;
  try{
   const len=Number(req.headers['content-length']);
   check(req.method==='POST'&&req.headers.origin===undefined&&req.headers['transfer-encoding']===undefined&&req.headers['content-type']==='application/json'&&Number.isInteger(len)&&len>=1&&len<=32768);
   const chunks=[];let n=0;for await(const b of req){n+=b.length;check(n<=len);chunks.push(b);}
   check(n===len);
   const body=JSON.parse(new TextDecoder('utf8',{fatal:true}).decode(Buffer.concat(chunks,n)));
   check(body?.simulationOnly===true);
   check(exact(body,['simulationOnly','scope','input'])&&body.scope===network);
   const action={'/api/quantic/pay-replica-lab/v1/status':'status','/api/quantic/pay-replica-lab/v1/admit':'admit','/api/quantic/pay-replica-lab/v1/vote-admission':'voteAdmission','/api/quantic/pay-replica-lab/v1/admission-report':'admissionReport','/api/quantic/pay-replica-lab/v1/prepare':'prepare','/api/quantic/pay-replica-lab/v1/change-view':'changeView','/api/quantic/pay-replica-lab/v1/commit':'commit','/api/quantic/pay-replica-lab/v1/learn':'learn','/api/quantic/pay-replica-lab/v1/upload-begin':'uploadBegin','/api/quantic/pay-replica-lab/v1/upload-chunk':'uploadChunk','/api/quantic/pay-replica-lab/v1/upload-finish':'uploadFinish','/api/quantic/pay-replica-lab/v1/record-begin':'recordBegin','/api/quantic/pay-replica-lab/v1/record-chunk':'recordChunk'}[req.url];
   if(!['status','admissionReport','voteAdmission','admit','prepare','changeView','commit','learn','uploadBegin','uploadChunk','uploadFinish','recordBegin','recordChunk'].includes(action)){send(404,{});return;}
   let output;
   if(action==='uploadBegin')output=upload.begin(body.input);
   else if(action==='uploadChunk')output=upload.chunk(body.input);
   else if(action==='uploadFinish'){const payload=upload.finish(body.input);output=dispatch(payload.op,payload.input);}
   else if(action==='recordBegin')output=download.begin(body.input);
   else if(action==='recordChunk')output=download.chunk(body.input);
   else output=dispatch(action,body.input);
   const reply={simulationOnly:true,scope:network,output,realPaymentAuthorized:false};
   check(Buffer.byteLength(JSON.stringify(reply))<=32768);
   send(200,reply);
  }catch{if(!res.headersSent&&!res.destroyed)send(400,{});}
  finally{busy=false;}
 });
 server.maxConnections=8;server.requestTimeout=5000;server.headersTimeout=3000;server.setTimeout(6000,s=>s.destroy());
 try{await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(c.port,'127.0.0.1',resolve);});}
 catch(e){store.close();throw e;}
 console.log('READY PAY REPLICA LAB '+c.port);
 let stopping=false;
 function stop(){if(stopping)return;stopping=true;server.closeAllConnections();server.close(()=>{auth.fill(0);upload.clear();download.clear();store.close();});}
 process.once('SIGTERM',stop);process.once('SIGINT',stop);
}
main().catch(()=>{console.error('Pay round witness laboratory refused');process.exitCode=1;});
