// Local trusted client for explicit native relay mode. No signing or key access.
import {request} from 'node:http';
import {nativeRecordDigest,normalizeNativeRecord} from '../lib/quantic/native-mailbox.mjs';
const check=(x)=>{if(!x)throw Error('Native mailbox operation not confirmed');};
export function createNativeMailboxClient({endpoint,address,deviceId,token}){
 const u=new URL(endpoint);
 check(u.protocol==='http:'&&u.hostname==='127.0.0.1'&&u.port&&u.pathname==='/'&&!u.username&&!u.password&&!u.search&&!u.hash);
 check(typeof address==='string'&&/^[a-z0-9][a-z0-9._-]{2,31}~[a-f0-9]{32}@quantic$/.test(address)&&typeof deviceId==='string'&&/^d-[a-f0-9]{32}$/.test(deviceId));
 check(typeof token==='string'&&/^[A-Za-z0-9._~-]{40,256}$/.test(token));
 function call(op,body){
  const raw=Buffer.from(JSON.stringify(body));check(raw.length<=32768);
  return new Promise((resolve,reject)=>{
   const req=request(new URL('/api/quantic/native/v1/'+op,u),{method:'POST',agent:false,headers:{'Content-Type':'application/json','Content-Length':raw.length,Authorization:'Bearer '+token,Connection:'close'}},res=>{
    if(res.statusCode!==(op==='send'?202:200)){res.destroy();reject(Error('Native relay refused'));return;}
    let length=0;const chunks=[];
    res.on('data',c=>{length+=c.length;if(length>32768){res.destroy(Error('Native relay response too large'));return;}chunks.push(c);});
    res.on('error',reject);
    res.on('end',()=>{try{resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));}catch(e){reject(e);}});
   });
   const timer=setTimeout(()=>req.destroy(Error('Native relay deadline')),20000);
   req.on('close',()=>clearTimeout(timer));req.on('error',reject);req.end(raw);
  });
 }
 function responseStatus(result,digest,id){
  check(result&&typeof result.id==='string'&&/^[0-9a-f-]{36}$/.test(result.id)&&(!id||id===result.id)&&result.digest===digest&&['queued','acknowledged'].includes(result.status)&&typeof result.duplicate==='boolean');return result;
 }
 function item(result,id,digest){
  if(result?.item===null&&!id)return null;
  const r=result?.item;check(r&&(!id||r.id===id)&&(!digest||r.digest===digest)&&nativeRecordDigest(r.record)===r.digest&&r.record.context.to===address&&r.record.context.toDeviceId===deviceId);
  return r;
 }
 return Object.freeze({
  async send(record){
   const normalized=normalizeNativeRecord(record);
   check(normalized.context.from===address&&normalized.context.fromDeviceId===deviceId);
   return responseStatus(await call('send',normalized),nativeRecordDigest(normalized));
  },
  async pull(){return item(await call('pull',{address,deviceId}));},
  async ack(id,digest){const r=responseStatus(await call('ack',{address,deviceId,id,digest}),digest,id);check(r.status==='acknowledged');return r;},
  async recover(id,digest){return item(await call('recover',{address,deviceId,id,digest}),id,digest);}
 });
}
