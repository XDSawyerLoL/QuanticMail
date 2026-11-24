// End-to-end payload protection for the synthetic trusted-routing mux.
// Endpoint-only PSKs, freshly provisioned epoch and direction; key distribution,
// persistence, anonymous routing, and PQ handshake are intentionally out of scope.
// A gateway may see membership, timing, routes and opaque envelopes, never the PSK.
import {createCipheriv,createDecipheriv,hkdfSync,randomBytes} from 'node:crypto';
export const E2E_POLICY=Object.freeze({frame:78,payload:44,maxSeq:8192});
const check=v=>{if(!v)throw Error('Endpoint envelope refused');};
const id=v=>typeof v==='string'&&/^demo-[a-z0-9]{1,24}$/.test(v);
function channel({secret,epoch,from,to}){
 check(Buffer.isBuffer(secret)&&secret.length===32&&Buffer.isBuffer(epoch)&&epoch.length===32&&id(from)&&id(to)&&from!==to);
 const aad=Buffer.from(JSON.stringify(['quantic-mux-endpoint/lab/v1',epoch.toString('hex'),from,to]));
 const key=Buffer.from(hkdfSync('sha256',secret,epoch,aad,32));
 let seq=0,closed=false;
 return {key,aad,next(){check(!closed&&seq<E2E_POLICY.maxSeq);return seq;},advance(){seq++;},close(){closed=true;key.fill(0);}};
}
export function openEndpointSender(config){
 const c=channel(config);
 return Object.freeze({
  seal(data){
   const seq=c.next();check(Buffer.isBuffer(data)&&data.length>=1&&data.length<=E2E_POLICY.payload);
   const p=randomBytes(50),nonce=randomBytes(12);
   try{
    p.writeUInt32BE(seq,0);p.writeUInt16BE(data.length,4);data.copy(p,6);
    const enc=createCipheriv('aes-256-gcm',c.key,nonce);enc.setAAD(c.aad);
    const frame=Buffer.concat([nonce,enc.update(p),enc.final(),enc.getAuthTag()]);
    check(frame.length===E2E_POLICY.frame);c.advance();return frame;
   }finally{p.fill(0);}
  },close:c.close
 });
}
export function openEndpointReceiver(config){
 const c=channel(config);
 return Object.freeze({
  open(frame){
   const seq=c.next();check(Buffer.isBuffer(frame)&&frame.length===E2E_POLICY.frame);
   let p;
   try{
    const d=createDecipheriv('aes-256-gcm',c.key,frame.subarray(0,12));d.setAAD(c.aad);d.setAuthTag(frame.subarray(62));
    p=Buffer.concat([d.update(frame.subarray(12,62)),d.final()]);
    const len=p.readUInt16BE(4);
    if(p.readUInt32BE(0)!==seq||len<1||len>E2E_POLICY.payload)return null;
    const data=Buffer.from(p.subarray(6,6+len));c.advance();return data;
   }catch{return null;}finally{p?.fill(0);}
  },close:c.close
 });
}
