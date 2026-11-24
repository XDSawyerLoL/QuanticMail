// Local trusted client for explicit native relay mode. No signing or key access.
import {request} from 'node:http';
import {nativeRecordDigest,normalizeNativeRecord} from '../lib/quantic/native-mailbox.mjs';
const uuid=/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const hex=/^[0-9a-f]{64}$/;
const check=(x)=>{if(!x)throw Error('Native mailbox operation not confirmed');};
export function createNativeMailboxClient({endpoint,address,deviceId,token,credentialMode},{transport}={}){
 const u=new URL(endpoint);
 check(u.protocol==='http:'&&u.hostname==='127.0.0.1'&&u.port&&u.pathname==='/'&&!u.username&&!u.password&&!u.search&&!u.hash);
 check(typeof address==='string'&&/^[a-z0-9][a-z0-9._-]{2,31}~[a-f0-9]{32}@quantic$/.test(address)&&typeof deviceId==='string'&&/^d-[a-f0-9]{32}$/.test(deviceId));
 if(credentialMode==='vault-sealed-v1'){check(token===undefined&&typeof transport==='function');}else{check(credentialMode===undefined&&transport===undefined&&typeof token==='string'&&/^[A-Za-z0-9._~-]{40,256}$/.test(token));}
 function call(op,body){
  if(credentialMode==='vault-sealed-v1')return transport(op,body);
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
  check(result&&typeof result.id==='string'&&uuid.test(result.id)&&(!id||id===result.id)&&result.digest===digest&&['queued','acknowledged'].includes(result.status)&&typeof result.duplicate==='boolean');return result;
 }
 function item(result,id,digest){
  if(result?.item===null&&!id)return null;
  const r=result?.item;check(r&&uuid.test(r.id)&&hex.test(r.digest)&&Number.isSafeInteger(r.queuedAt)&&r.queuedAt>0&&(r.acknowledgedAt===null||Number.isSafeInteger(r.acknowledgedAt)&&r.acknowledgedAt>=r.queuedAt)&&(!id||r.id===id)&&(!digest||r.digest===digest));
  const record=normalizeNativeRecord(r.record);
  check(nativeRecordDigest(record)===r.digest&&record.context.to===address&&record.context.toDeviceId===deviceId);
  return {...r,record};
 }
 return Object.freeze({
  async send(record){
   const normalized=normalizeNativeRecord(record);
   check(normalized.context.from===address&&normalized.context.fromDeviceId===deviceId);
   return responseStatus(await call('send',normalized),nativeRecordDigest(normalized));
  },
  async pull(){return item(await call('pull',{address,deviceId}));},
  async ack(id,digest){check(uuid.test(id)&&hex.test(digest));const r=responseStatus(await call('ack',{address,deviceId,id,digest}),digest,id);check(r.status==='acknowledged');return r;},
  async recover(id,digest){check(uuid.test(id)&&hex.test(digest));return item(await call('recover',{address,deviceId,id,digest}),id,digest);}
 });
}
