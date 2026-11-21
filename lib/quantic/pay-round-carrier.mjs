// Bounded, explicit loopback client for the separate round-lab carrier.
// No retries, external destinations, or fallback to an unprotected endpoint.
import {request} from 'node:http';
const check=v=>{if(!v)throw Error('Pay round carrier refused');};
const MAX=32768;
export function createPayRoundCarrier({loopbackPort,token,scope}){
 check(Number.isInteger(loopbackPort)&&loopbackPort>=1&&loopbackPort<=65535&&typeof token==='string'&&/^[a-f0-9]{64}$/.test(token)&&typeof scope==='string'&&/^[a-f0-9]{64}$/.test(scope));
 let busy=false;
 async function call(op,input){
  check(!busy);const body=Buffer.from(JSON.stringify({simulationOnly:true,scope,input}));check(body.length<=MAX);busy=true;
  try{
   return await new Promise((resolve,reject)=>{
    const q=request({hostname:'127.0.0.1',port:loopbackPort,path:'/api/quantic/pay-round-lab/v1/'+op,method:'POST',agent:false,headers:{'Content-Type':'application/json','Content-Length':body.length,Authorization:'Bearer '+token,Connection:'close'}},async res=>{
     try{
      check(res.statusCode===200);
      const parts=[];let n=0;for await(const b of res){n+=b.length;check(n<=MAX);parts.push(b);}
      const data=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(Buffer.concat(parts,n)));
      check(data.simulationOnly===true&&data.scope===scope&&data.realPaymentAuthorized===false&&Object.hasOwn(data,'output'));
      resolve(data.output);
     }catch(e){res.destroy();reject(e);}
    });
    const timer=setTimeout(()=>q.destroy(Error('Round carrier deadline')),19000);
    q.once('close',()=>clearTimeout(timer));q.once('error',reject);q.end(body);
   });
  }finally{busy=false;}
 }
 return Object.freeze({status:()=>call('status',null),prepare:i=>call('prepare',i),changeView:i=>call('change-view',i),commit:i=>call('commit',i),learn:i=>call('learn',i)});
}
