// Synthetic-only extra AEAD layer for the second relay.
// NOT an audited onion protocol: colluding relays can still correlate.
import {createCipheriv,createDecipheriv,randomBytes} from 'node:crypto';
import {sealEndToEndLab,E2E_LAB} from './scattering-e2e-envelope-lab.mjs';
import {sealReliable,openReliable} from '../../labs/quantic-native/scattering/scattering-reliable-lab.mjs';
const aad=Buffer.from('quantic-scattering-lab/second-hop/v1');
const keyOK=k=>Buffer.isBuffer(k)&&k.length===32;
const check=(v,msg)=>{if(!v)throw Error(msg)};
export const SECOND_LAYER_BYTES=120;
export function wrapSecondLayer(key,inner){
 check(keyOK(key)&&Buffer.isBuffer(inner)&&inner.length===E2E_LAB.innerLength,'invalid second layer input');
 const nonce=randomBytes(12),c=createCipheriv('aes-256-gcm',key,nonce);c.setAAD(aad);
 return Buffer.concat([nonce,c.update(inner),c.final(),c.getAuthTag()]);
}
export function peelSecondLayer(key,wrapped){
 if(!keyOK(key)||!Buffer.isBuffer(wrapped)||wrapped.length!==SECOND_LAYER_BYTES)return null;
 let interim;
 try{
  const d=createDecipheriv('aes-256-gcm',key,wrapped.subarray(0,12));
  d.setAAD(aad);d.setAuthTag(wrapped.subarray(-16));
  interim=d.update(wrapped.subarray(12,-16));
  return Buffer.concat([interim,d.final()]);
 }catch{return null;}finally{interim?.fill(0);}
}
export function sealLayeredLab({hopKey,secondKey,endToEndKey,senderId,seq,data}){
 check([hopKey,secondKey,endToEndKey].every(keyOK)&&
  !hopKey.equals(secondKey)&&!hopKey.equals(endToEndKey)&&!secondKey.equals(endToEndKey),'distinct layer keys required');
 const inner=sealEndToEndLab(endToEndKey,{senderId,seq,data});
 let wrapped;
 try{wrapped=wrapSecondLayer(secondKey,inner);return sealReliable(hopKey,{seq,ack:0,data:wrapped});}
 finally{inner.fill(0);wrapped?.fill(0);}
}
export function peelAndResealLab({inputKey,secondKey,outputKey,packet,hopSeq}){
 check([inputKey,secondKey,outputKey].every(keyOK)&&
  !inputKey.equals(secondKey)&&!inputKey.equals(outputKey)&&!secondKey.equals(outputKey),'distinct relay keys required');
 const ingress=openReliable(inputKey,packet);
 if(!ingress||ingress.seq===null)return null;
 let inner;
 try{
  inner=peelSecondLayer(secondKey,ingress.data);
  if(!inner)return null;
  return sealReliable(outputKey,{seq:hopSeq,ack:0,data:inner});
 }finally{ingress.data.fill(0);inner?.fill(0);}
}
