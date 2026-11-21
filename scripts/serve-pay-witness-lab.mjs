// One separately provisioned fictional Pay witness, local carrier ingress only.
// Run one instance per laboratory machine with a different key and database.
import {createServer} from 'node:http';
import {createPrivateKey,timingSafeEqual} from 'node:crypto';
import {lstatSync,realpathSync,openSync,readFileSync,closeSync,fstatSync,constants} from 'node:fs';
import {isAbsolute} from 'node:path';
import {openPayWitnessStore} from '../lib/quantic/pay-witness-store.mjs';
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
 const raw=privateRead(process.argv[3],16384);let c;
 try{c=JSON.parse(raw.toString('utf8'));}finally{raw.fill(0);}
 check(exact(c,['simulationOnly','directory','scope','authorityKeyFile','authorityPin','token','port'])&&c.simulationOnly===true&&Number.isInteger(c.port)&&c.port>=1&&c.port<=65535&&typeof c.token==='string'&&/^[a-f0-9]{64}$/.test(c.token));
 check(exact(c.scope,['signingPin','pqPin']));
 const secret=privateRead(c.authorityKeyFile,8192);
 let key;try{key=createPrivateKey(secret);}finally{secret.fill(0);}
 const options={directory:c.directory,scope:c.scope,authorityPrivateKey:key,expectedAuthorityPin:c.authorityPin};
 const store=openPayWitnessStore({...options,createNew:process.argv[2]==='provision'});
 if(process.argv[2]==='provision'){store.close();console.log('PROVISIONED PAY LAB');return;}
 const auth=Buffer.from('Bearer '+c.token);delete c.token;
 let busy=false;
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
   if(req.url==='/api/quantic/pay-lab/v1/checkpoint'){
    check(exact(body,['simulationOnly','checkpoint']));
    send(200,{simulationOnly:true,attestations:[store.vote(body.checkpoint)]});
   }else if(req.url==='/api/quantic/pay-lab/v1/submit'){
    check(exact(body,['simulationOnly','proof','prior']));
    store.append(body.proof,body.prior);
    send(200,{simulationOnly:true,accepted:true,realPaymentAuthorized:false});
   }else send(404,{});
  }catch{if(!res.headersSent&&!res.destroyed)send(400,{});}
  finally{busy=false;}
 });
 server.maxConnections=8;server.requestTimeout=5000;server.headersTimeout=3000;server.setTimeout(6000,s=>s.destroy());
 try{await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(c.port,'127.0.0.1',resolve);});}
 catch(e){store.close();throw e;}
 console.log('READY PAY LAB '+c.port);
 let stopping=false;
 function stop(){if(stopping)return;stopping=true;server.closeAllConnections();server.close(()=>{auth.fill(0);store.close();});}
 process.once('SIGTERM',stop);process.once('SIGINT',stop);
}
main().catch(()=>{console.error('Pay witness laboratory refused');process.exitCode=1;});
