// Bounded, explicit loopback client for the separate round-lab carrier.
// No retries, external destinations, or fallback to an unprotected endpoint.
import {request} from 'node:http';
import {encodeRoundPrepare,ROUND_TRANSFER_CHUNK} from './pay-round-transfer.mjs';
const check=v=>{if(!v)throw Error('Pay round carrier refused');};
const MAX=32768;
export function createPayRoundCarrier({loopbackPort,token,scope}){
 check(Number.isInteger(loopbackPort)&&loopbackPort>=1&&loopbackPort<=65535&&typeof token==='string'&&/^[a-f0-9]{64}$/.test(token)&&typeof scope==='string'&&/^[a-f0-9]{64}$/.test(scope));
 let busy=false;
 async function send(op,input){
  const body=Buffer.from(JSON.stringify({simulationOnly:true,scope,input}));check(body.length<=MAX);
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
  }finally{body.fill(0);}
 }
 async function call(op,input){
  check(!busy);busy=true;
  try{
   const snapshot=structuredClone(input);
   if(op!=='prepare'||Buffer.byteLength(JSON.stringify({simulationOnly:true,scope,input:snapshot}))<=MAX)return await send(op,snapshot);
   const {raw,size,digest}=encodeRoundPrepare(snapshot);
   try{
    const begin=await send('upload-begin',{size,digest});
    check(typeof begin?.id==='string'&&/^[a-f0-9]{64}$/.test(begin.id)&&begin.offset===0);
    for(let offset=0;offset<size;offset+=ROUND_TRANSFER_CHUNK){
     const end=Math.min(size,offset+ROUND_TRANSFER_CHUNK);
     const got=await send('upload-chunk',{id:begin.id,offset,data:raw.subarray(offset,end).toString('base64url')});
     check(got?.id===begin.id&&got.offset===end);
    }
    return await send('upload-finish',{id:begin.id});
   }finally{raw.fill(0);}
  }finally{busy=false;}
 }
 return Object.freeze({status:()=>call('status',null),prepare:i=>call('prepare',i),changeView:i=>call('change-view',i),commit:i=>call('commit',i),learn:i=>call('learn',i)});
}
