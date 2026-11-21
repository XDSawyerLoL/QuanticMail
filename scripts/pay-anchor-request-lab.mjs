// Child process so the synchronous replica guard cannot release a vote
// while waiting for external durable acknowledgement.
import {request} from 'node:https';
import {readFileSync} from 'node:fs';
import {check,exact,hex,port,config,privateRead} from '../lib/quantic/pay-anchor-config.mjs';
async function main(){
 check(process.argv.length===4&&['read','cas'].includes(process.argv[2]));
 const c=config(process.argv[3]);check(exact(c,['simulationOnly','network','authorityPin','port','token','certFile'])&&c.simulationOnly===true&&hex(c.network)&&hex(c.authorityPin)&&hex(c.token)&&port(c.port));
 const raw=readFileSync(0);check(raw.length<=8192);
 const input=JSON.parse(raw.toString('utf8'));raw.fill(0);
 const body=Buffer.from(JSON.stringify({simulationOnly:true,network:c.network,authorityPin:c.authorityPin,input}));check(body.length<=8192);
 const cert=privateRead(c.certFile,16384);
 const result=await new Promise((resolve,reject)=>{
  const q=request({hostname:'127.0.0.1',port:c.port,method:'POST',path:'/v1/'+process.argv[2],agent:false,ca:cert,rejectUnauthorized:true,minVersion:'TLSv1.3',headers:{Authorization:'Bearer '+c.token,'Content-Type':'application/json','Content-Length':body.length,Connection:'close'}},async res=>{
   try{check(res.statusCode===200);const parts=[];let n=0;for await(const b of res){n+=b.length;check(n<=8192);parts.push(b);}
    const x=JSON.parse(new TextDecoder('utf8',{fatal:true}).decode(Buffer.concat(parts,n)));
    check(exact(x,['simulationOnly','network','authorityPin','output'])&&x.simulationOnly===true&&x.network===c.network&&x.authorityPin===c.authorityPin);resolve(x.output);
   }catch(e){res.destroy();reject(e);}
  });
  const timer=setTimeout(()=>q.destroy(Error('anchor deadline')),5000);
  q.once('close',()=>clearTimeout(timer));q.once('error',reject);q.end(body);
 });
 process.stdout.write(JSON.stringify(result));
}
main().catch(()=>{console.error('Pay anchor request refused');process.exitCode=1;});
