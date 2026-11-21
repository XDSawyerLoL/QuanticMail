// Separate authenticated TLS checkpoint service, loopback lab only.
import {createServer} from 'node:https';
import {timingSafeEqual} from 'node:crypto';
import {openPayAnchorStore} from '../lib/quantic/pay-anchor-store.mjs';
import {check,exact,hex,port,config,privateRead} from '../lib/quantic/pay-anchor-config.mjs';
async function main(){
 check(process.argv.length===4&&['provision','serve'].includes(process.argv[2]));
 const c=config(process.argv[3]);check(exact(c,['simulationOnly','directory','initial','port','token','keyFile','certFile'])&&c.simulationOnly===true&&port(c.port)&&hex(c.token));
 const tlsKey=privateRead(c.keyFile,16384),tlsCert=privateRead(c.certFile,16384);
 const store=openPayAnchorStore({directory:c.directory,initial:c.initial,createNew:process.argv[2]==='provision'});
 if(process.argv[2]==='provision'){store.close();tlsKey.fill(0);console.log('PROVISIONED PAY ANCHOR LAB');return;}
 const auth=Buffer.from('Bearer '+c.token);delete c.token;
 let busy=false;
 const server=createServer({key:tlsKey,cert:tlsCert,minVersion:'TLSv1.3'},async(req,res)=>{
  const reply=(status,body)=>{const b=Buffer.from(JSON.stringify(body));res.writeHead(status,{'Content-Type':'application/json','Content-Length':b.length,'Cache-Control':'no-store',Connection:'close'});res.end(b);};
  const header=Buffer.from(req.headers.authorization??'');
  if(header.length!==auth.length||!timingSafeEqual(header,auth)){req.resume();reply(401,{});return;}
  if(busy){req.resume();reply(503,{});return;}busy=true;
  try{
   const length=Number(req.headers['content-length']);
   check(req.method==='POST'&&req.headers.origin===undefined&&req.headers['transfer-encoding']===undefined&&req.headers['content-type']==='application/json'&&Number.isInteger(length)&&length>=1&&length<=8192);
   const parts=[];let n=0;for await(const b of req){n+=b.length;check(n<=length);parts.push(b);}check(n===length);
   const body=JSON.parse(new TextDecoder('utf8',{fatal:true}).decode(Buffer.concat(parts,n)));
   check(exact(body,['simulationOnly','network','authorityPin','input'])&&body.simulationOnly===true&&body.network===c.initial.network&&body.authorityPin===c.initial.authorityPin);
   let output;
   if(req.url==='/v1/read'){check(body.input===null);output=store.read();}
   else if(req.url==='/v1/cas'){check(exact(body.input,['before','after']));output=store.compareAndSwap(body.input.before,body.input.after);}
   else throw Error('route');
   reply(200,{simulationOnly:true,network:body.network,authorityPin:body.authorityPin,output});
  }catch{if(!res.headersSent&&!res.destroyed)reply(400,{});}
  finally{busy=false;}
 });
 tlsKey.fill(0);
 server.maxConnections=8;server.requestTimeout=3000;server.headersTimeout=2000;server.setTimeout(5000,s=>s.destroy());
 try{await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(c.port,'127.0.0.1',resolve);});}catch(e){store.close();throw e;}
 console.log('READY PAY ANCHOR LAB');
 let stopping=false;const stop=()=>{if(stopping)return;stopping=true;server.closeAllConnections();server.close(()=>{auth.fill(0);store.close();});};
 process.once('SIGTERM',stop);process.once('SIGINT',stop);
}
main().catch(()=>{console.error('Pay anchor laboratory refused');process.exitCode=1;});
