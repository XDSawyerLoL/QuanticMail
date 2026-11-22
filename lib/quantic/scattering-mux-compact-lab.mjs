// Lab only: authenticated outer hop required; access authentication is external.
// Gateway sees route labels and opaque envelopes, not endpoint keys or payloads.
// Fresh endpoint epochs and independent PSKs must be provisioned out of band.
import {createCipheriv,createDecipheriv,hkdfSync,randomBytes} from 'node:crypto';
export const COMPACT_MUX=Object.freeze({frame:128,payload:78,maxSeq:8192,maxRoutes:64,maxPerRoute:32,maxTotal:512});
const P=COMPACT_MUX,check=x=>{if(!x)throw Error('Compact mux refused');};
const labelOK=x=>Buffer.isBuffer(x)&&x.length===16;
function endpoint({secret,epoch,label,direction},sender){
 check(Buffer.isBuffer(secret)&&secret.length===32&&Buffer.isBuffer(epoch)&&epoch.length===32&&labelOK(label)&&['a-b','b-a'].includes(direction));
 label=Buffer.from(label);
 const aad=Buffer.concat([Buffer.from('quantic-compact-mux/lab/v1:'+direction+'\0'),epoch,label]);
 const key=Buffer.from(hkdfSync('sha256',secret,epoch,aad,32));let seq=0,closed=false;
 function seal(data){
  check(!closed&&sender&&seq<P.maxSeq&&Buffer.isBuffer(data)&&data.length>=1&&data.length<=P.payload);
  const p=randomBytes(84),nonce=randomBytes(12);try{
   p.writeUInt32BE(seq,0);p.writeUInt16BE(data.length,4);data.copy(p,6);
   const c=createCipheriv('aes-256-gcm',key,nonce);c.setAAD(aad);
   const b=Buffer.concat([label,nonce,c.update(p),c.final(),c.getAuthTag()]);seq++;return b;
  }finally{p.fill(0);}
 }
 function open(b){
  check(!closed&&!sender&&Buffer.isBuffer(b)&&b.length===P.frame);
  if(seq>=P.maxSeq||!b.subarray(0,16).equals(label))return null;
  let p;try{
   const d=createDecipheriv('aes-256-gcm',key,b.subarray(16,28));d.setAAD(aad);d.setAuthTag(b.subarray(112));
   p=Buffer.concat([d.update(b.subarray(28,112)),d.final()]);const n=p.readUInt16BE(4);
   if(p.readUInt32BE(0)!==seq||n<1||n>P.payload)return null;
   const data=Buffer.from(p.subarray(6,6+n));seq++;return data;
  }catch{return null;}finally{p?.fill(0);}
 }
 return Object.freeze({...(sender?{seal}:{open}),close(){closed=true;key.fill(0);}});
}
export const openCompactSender=c=>endpoint(c,true);
export const openCompactReceiver=c=>endpoint(c,false);
export function openOpaqueRouter(labels){
 check(Array.isArray(labels)&&labels.length>=2&&labels.length<=P.maxRoutes&&labels.every(labelOK));
 const routes=new Map();for(const l of labels){const id=l.toString('hex');check(!routes.has(id));routes.set(id,[]);}
 const queues=[...routes.values()];let cursor=0,queued=0,slots=0,closed=false;
 return Object.freeze({
  // Caller must authenticate access and bind it to the permitted route label.
  enqueue(authorizedLabel,b){
   check(!closed&&labelOK(authorizedLabel)&&Buffer.isBuffer(b)&&b.length===P.frame&&b.subarray(0,16).equals(authorizedLabel));
   const q=routes.get(authorizedLabel.toString('hex'));check(q&&q.length<P.maxPerRoute&&queued<P.maxTotal);q.push(Buffer.from(b));queued++;
  },
  nextSlot(){check(!closed);slots++;for(let i=0;i<queues.length;i++){const j=(cursor+i)%queues.length,q=queues[j];if(q.length){cursor=(j+1)%queues.length;queued--;return q.shift();}}return randomBytes(P.frame);},
  stats:()=>Object.freeze({queued,slots}),close(){closed=true;queued=0;for(const q of queues){for(const b of q)b.fill(0);q.length=0;}routes.clear();}
 });
}
