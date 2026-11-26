// Synthetic Windows restore rehearsal. Collection content is encrypted
// before it reaches the native NTFS helper. Key and trusted root pin are
// supplied separately, never embedded in disk records or command arguments.
// Not an import format and never an authority for native account activation.
import {createCipheriv,createDecipheriv,randomBytes} from 'node:crypto';
const deny=ok=>{if(!ok)throw Error('Sealed Windows migration rehearsal refused');};
const scope=/^[a-f0-9]{64}$/;
const names=['messages','contacts','prekeys','outbox'];
const domain='quantic-native-migration-collections-lab/v1';
const maxPlain=96000;
const maxSealed=131072;
const enc=b=>b.toString('base64url');
function decode(s,min,max){
 deny(typeof s==='string'&&/^[A-Za-z0-9_-]+$/.test(s)&&s.length<=Math.ceil(max/3)*4);
 const b=Buffer.from(s,'base64url');
 deny(b.length>=min&&b.length<=max&&enc(b)===s);return b;
}
function validateCollections(v){
 deny(v&&Object.getPrototypeOf(v)===Object.prototype&&Object.keys(v).length===names.length);
 for(const name of names){
  deny(Array.isArray(v[name])&&v[name].length<=10000);
  for(const row of v[name])deny(row&&Object.getPrototypeOf(row)===Object.prototype);
 }
 return v;
}
function assertScope({rootPin,role}){
 deny(scope.test(rootPin)&&(role==='source'||role==='candidate'));
 return Buffer.from(JSON.stringify([domain,rootPin,role]));
}
export function sealMigrationCollections(collections,key,{rootPin,role}){
 deny(Buffer.isBuffer(key)&&key.length===32);
 const aad=assertScope({rootPin,role});validateCollections(collections);
 const raw=Buffer.from(JSON.stringify(collections),'utf8');deny(raw.length>0&&raw.length<=maxPlain);
 try{
  const iv=randomBytes(12),c=createCipheriv('aes-256-gcm',key,iv);c.setAAD(aad);
  const ciphertext=Buffer.concat([c.update(raw),c.final()]);
  const packed=Buffer.from(JSON.stringify({format:domain,version:1,iv:enc(iv),ciphertext:enc(ciphertext),tag:enc(c.getAuthTag())}));
  deny(packed.length<=maxSealed);return packed;
 }finally{raw.fill(0);}
}
export function openMigrationCollections(packed,key,{rootPin,role}){
 deny(Buffer.isBuffer(key)&&key.length===32&&Buffer.isBuffer(packed)&&packed.length<=maxSealed);
 const aad=assertScope({rootPin,role});
 const p=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(packed));
 deny(p&&Object.getPrototypeOf(p)===Object.prototype&&Object.keys(p).length===5&&p.format===domain&&p.version===1);
 const iv=decode(p.iv,12,12),tag=decode(p.tag,16,16),ciphertext=decode(p.ciphertext,1,maxPlain+16);
 let first,last,raw;
 try{
  const d=createDecipheriv('aes-256-gcm',key,iv);d.setAAD(aad);d.setAuthTag(tag);
  first=d.update(ciphertext);last=d.final();raw=Buffer.concat([first,last]);
  deny(raw.length>=1&&raw.length<=maxPlain);
  const collections=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(raw));
  return validateCollections(collections);
 }finally{first?.fill(0);last?.fill(0);raw?.fill(0);}
}
