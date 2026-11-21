// Only the dedicated lab carrier's loopback client endpoint is accepted.
// No direct remote HTTP fallback, PSP integration, or production payment.
import {request} from 'node:http';
const check=v=>{if(!v)throw Error('Pay Scattering laboratory refused');};
const MAX=32768;
export function createPayScatteringClient({loopbackPort,token}){
 check(Number.isInteger(loopbackPort)&&loopbackPort>=1&&loopbackPort<=65535&&typeof token==='string'&&/^[A-Za-z0-9._~-]{40,256}$/.test(token));
 let busy=false,halted=false;
 async function send(op,value){
  check(!busy&&!halted);busy=true;
  try{
   const body=Buffer.from(JSON.stringify(value));check(body.length>=1&&body.length<=MAX);
   return await new Promise((resolve,reject)=>{
    const q=request({hostname:'127.0.0.1',port:loopbackPort,path:'/api/quantic/pay-lab/v1/'+op,method:'POST',agent:false,headers:{'Content-Type':'application/json','Content-Length':body.length,Authorization:'Bearer '+token,Connection:'close'}},async res=>{
     try{
      check(res.statusCode===200);
      const parts=[];let n=0;
      for await(const b of res){n+=b.length;check(n<=MAX);parts.push(b);}
      resolve(JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(Buffer.concat(parts,n))));
     }catch(e){res.destroy();reject(e);}
    });
    const timer=setTimeout(()=>q.destroy(Error('Pay Scattering deadline')),19000);
    q.once('close',()=>clearTimeout(timer));q.once('error',reject);q.end(body);
   });
  }catch(e){halted=true;throw e;}finally{busy=false;}
 }
 return Object.freeze({
  async readVotes(checkpoint){const r=await send('checkpoint',{simulationOnly:true,checkpoint});check(r?.simulationOnly===true&&Array.isArray(r.attestations)&&r.attestations.length<=4);return r.attestations;},
  async submitProof(proof,prior){const r=await send('submit',{simulationOnly:true,proof,prior});check(r?.simulationOnly===true&&r.accepted===true&&r.realPaymentAuthorized===false);},
 });
}
