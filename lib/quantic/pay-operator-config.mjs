// Explicit fictional native-v1 lab policy, independently pinned as raw bytes.
// No live endpoints, arbitrary destination accounts or real-provider keys.
import {createHash,createPublicKey} from 'node:crypto';
const check=v=>{if(!v)throw Error('Pay operator configuration refused');};
const hex=/^[a-f0-9]{64}$/;
const exact=(o,keys)=>o&&typeof o==='object'&&!Array.isArray(o)&&Object.keys(o).length===keys.length&&keys.every(k=>Object.hasOwn(o,k));
const sha=b=>createHash('sha256').update(b).digest('hex');
function key(v,pin,type,n){
 check(typeof v==='string'&&v.length===Math.ceil(n*8/6)&&hex.test(pin)&&/^[A-Za-z0-9_-]+$/.test(v));
 const b=Buffer.from(v,'base64url');check(b.length===n&&b.toString('base64url')===v&&sha(b)===pin);
 const k=createPublicKey({key:b,type:'spki',format:'der'});check(k.asymmetricKeyType===type&&k.export({type:'spki',format:'der'}).equals(b));
}
export function parsePayOperatorConfig(raw,expectedPin){
 check(Buffer.isBuffer(raw)&&raw.length>0&&raw.length<=32768&&typeof expectedPin==='string'&&hex.test(expectedPin)&&sha(raw)===expectedPin);
 const c=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(raw));
 check(exact(c,['format','simulationOnly','scope','authorities'])&&c.format==='quantic-native-pay-operator/v1'&&c.simulationOnly===true);
 check(exact(c.scope,['signingPin','pqPin'])&&hex.test(c.scope.signingPin)&&hex.test(c.scope.pqPin)&&c.scope.signingPin!==c.scope.pqPin);
 check(Array.isArray(c.authorities)&&c.authorities.length===4);
 const used=new Set([c.scope.signingPin,c.scope.pqPin]),ports=new Set(),tokens=new Set(),trustedAuthorities=[],links=[];
 for(const a of c.authorities){
  check(exact(a,['pin','publicKey','pqPin','pqPublicKey','loopbackPort','token']));
  key(a.publicKey,a.pin,'ed25519',44);key(a.pqPublicKey,a.pqPin,'ml-dsa-65',1974);
  for(const p of [a.pin,a.pqPin]){check(!used.has(p));used.add(p);}
  check(Number.isInteger(a.loopbackPort)&&a.loopbackPort>=1024&&a.loopbackPort<=65535&&!ports.has(a.loopbackPort));
  check(typeof a.token==='string'&&hex.test(a.token)&&!tokens.has(a.token));
  ports.add(a.loopbackPort);tokens.add(a.token);
  trustedAuthorities.push(Object.freeze({pin:a.pin,publicKey:a.publicKey,pqPin:a.pqPin,pqPublicKey:a.pqPublicKey}));
  links.push(Object.freeze({loopbackPort:a.loopbackPort,token:a.token}));
 }
 return Object.freeze({scope:Object.freeze(c.scope),trustedAuthorities:Object.freeze(trustedAuthorities),links:Object.freeze(links)});
}
