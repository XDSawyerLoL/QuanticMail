// Experimental end-to-end ciphertext INSIDE per-hop authenticated 168-byte cells.
// The hop decrypts only an INNER CIPHERTEXT; not application plaintext.
// Not a production anonymous-messaging protocol. AES-256-GCM is not post-quantum.
import {createCipheriv,createDecipheriv,randomBytes} from 'node:crypto';
import {openReliable,sealReliable} from '../../labs/quantic-native/scattering/scattering-reliable-lab.mjs';

const AAD=Buffer.from('quantic-scattering-lab/e2e-inner/v1');
export const E2E_LAB=Object.freeze({dataLength:59,innerLength:92,outerLength:168,maxSequence:8192});
const validKey=k=>Buffer.isBuffer(k)&&k.length===32;
const check=(ok,why)=>{if(!ok)throw Error(why)};
export function sealEndToEndLab(key,{senderId,seq,data}){
 check(validKey(key)&&[0,1].includes(senderId)&&Number.isInteger(seq)&&seq>=0&&
  seq<E2E_LAB.maxSequence&&Buffer.isBuffer(data)&&data.length===E2E_LAB.dataLength,
  'invalid inner synthetic data or key');
 const plain=Buffer.alloc(64);
 plain[0]=senderId;plain.writeUInt32BE(seq,1);data.copy(plain,5);
 const nonce=randomBytes(12),cipher=createCipheriv('aes-256-gcm',key,nonce);
 cipher.setAAD(AAD);
 const ciphertext=Buffer.concat([cipher.update(plain),cipher.final()]);
 plain.fill(0);
 const sealed=Buffer.concat([nonce,ciphertext,cipher.getAuthTag()]);
 check(sealed.length===E2E_LAB.innerLength,'unexpected inner length');
 return sealed;
}
export function openEndToEndLab(key,inner){
 if(!validKey(key)||!Buffer.isBuffer(inner)||inner.length!==E2E_LAB.innerLength)return null;
 let plain;
 try{
  const cipher=createDecipheriv('aes-256-gcm',key,inner.subarray(0,12));
  cipher.setAAD(AAD);cipher.setAuthTag(inner.subarray(-16));
  plain=Buffer.concat([cipher.update(inner.subarray(12,-16)),cipher.final()]);
  if(plain.length!==64||![0,1].includes(plain[0])||plain.readUInt32BE(1)>=E2E_LAB.maxSequence)return null;
  return {senderId:plain[0],seq:plain.readUInt32BE(1),data:Buffer.from(plain.subarray(5))};
 }catch{return null;}
 finally{plain?.fill(0);}
}
export function sealNestedLab({hopKey,endToEndKey,senderId,seq,data}){
 const inner=sealEndToEndLab(endToEndKey,{senderId,seq,data});
 try{return sealReliable(hopKey,{seq,ack:0,data:inner});}
 finally{inner.fill(0);}
}
export function openNestedLab({hopKey,endToEndKey,packet}){
 const outer=openReliable(hopKey,packet);
 if(!outer||outer.seq===null||outer.data.length!==E2E_LAB.innerLength)return null;
 try{return openEndToEndLab(endToEndKey,outer.data);}
 finally{outer.data.fill(0);}
}
