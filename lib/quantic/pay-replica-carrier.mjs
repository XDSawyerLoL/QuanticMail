// Bounded, explicit loopback client for the separate round-lab carrier.
// No retries, external destinations, or fallback to an unprotected endpoint.
import {request} from 'node:http';
import {createHash} from 'node:crypto';
import {encodeRoundPrepare,ROUND_TRANSFER_CHUNK,ROUND_TRANSFER_MAX} from './pay-round-transfer.mjs';
const check=v=>{if(!v)throw Error('Pay round carrier refused');};
const MAX=32768;
export function createPayReplicaCarrier({loopbackPort,token,network:scope}){
 check(Number.isInteger(loopbackPort)&&loopbackPort>=1&&loopbackPort<=65535&&typeof token==='string'&&/^[a-f0-9]{64}$/.test(token)&&typeof scope==='string'&&/^[a-f0-9]{64}$/.test(scope));
 let busy=false;
 async function send(op,input){
  const body=Buffer.from(JSON.stringify({simulationOnly:true,scope,input}));check(body.length<=MAX);
  try{
   return await new Promise((resolve,reject)=>{
    const q=request({hostname:'127.0.0.1',port:loopbackPort,path:'/api/quantic/pay-replica-lab/v1/'+op,method:'POST',agent:false,headers:{'Content-Type':'application/json','Content-Length':body.length,Authorization:'Bearer '+token,Connection:'close'}},async res=>{
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
   if(!['prepare','learn','admit'].includes(op)||Buffer.byteLength(JSON.stringify({simulationOnly:true,scope,input:snapshot}))<=MAX)return await send(op,snapshot);
   const {raw,size,digest}=encodeRoundPrepare({op,input:snapshot});
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
 async function record(height){
  check(!busy&&Number.isInteger(height)&&height>=1&&height<=32);busy=true;
  let raw;
  try{
   const m=await send('record-begin',{height});
   check(m?.height===height&&typeof m.id==='string'&&/^[a-f0-9]{64}$/.test(m.id)&&typeof m.digest==='string'&&/^[a-f0-9]{64}$/.test(m.digest)&&Number.isInteger(m.size)&&m.size>=1&&m.size<=ROUND_TRANSFER_MAX);
   raw=Buffer.alloc(m.size);
   for(let offset=0;offset<m.size;offset+=ROUND_TRANSFER_CHUNK){
    const c=await send('record-chunk',{id:m.id,offset});
    check(c?.id===m.id&&c.offset===offset&&typeof c.data==='string'&&c.data.length<=24000&&/^[A-Za-z0-9_-]+$/.test(c.data));
    const b=Buffer.from(c.data,'base64url');
    try{check(b.toString('base64url')===c.data&&b.length===Math.min(ROUND_TRANSFER_CHUNK,m.size-offset));b.copy(raw,offset);}finally{b.fill(0);}
   }
   check(createHash('sha256').update(raw).digest('hex')===m.digest);
   return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(raw));
  }finally{raw?.fill(0);busy=false;}
 }
 return Object.freeze({record,status:()=>call('status',null),voteAdmission:i=>call('vote-admission',i),admit:i=>call('admit',i),prepare:i=>call('prepare',i),changeView:i=>call('change-view',i),commitVote:i=>call('commit',i),learn:i=>call('learn',i)});
}
