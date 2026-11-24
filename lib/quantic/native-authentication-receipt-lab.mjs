import {createHash,createPublicKey,verify} from 'node:crypto';
const check=x=>{if(!x)throw Error('Native authentication receipt refused');};
const sha=b=>createHash('sha256').update(b).digest('hex');
const hex=/^[a-f0-9]{64}$/;
const exact=(o,keys)=>check(o&&typeof o==='object'&&!Array.isArray(o)&&Object.keys(o).length===keys.length&&keys.every(k=>Object.hasOwn(o,k)));
export const authFormat='quantic-native-authentication-receipt-lab/v1';
const authFields=['format','authorityPin','address','deviceId','candidateDigest','clientPin','nonce','challengeSha256','issuedAt','expires'];
export function authBytes(r){
 exact(r,[...authFields,'signature']);check(r.format===authFormat);
 for(const k of ['authorityPin','candidateDigest','clientPin','nonce','challengeSha256'])check(typeof r[k]==='string'&&hex.test(r[k]));
 check(/^[a-z0-9][a-z0-9._-]{2,31}~[a-f0-9]{32}@quantic$/.test(r.address)&&/^d-[a-f0-9]{32}$/.test(r.deviceId));
 check(Number.isSafeInteger(r.issuedAt)&&r.expires===r.issuedAt+15000);
 return Buffer.from(JSON.stringify(authFields.map(k=>r[k])));
}
// This verifies fresh proof statements, NOT an access token or authorization.
export function verifyNativeAuthenticationQuorum({receipts,trusted,candidate,expected,clientPin,nonce,now=Date.now()}){
 check(hex.test(clientPin)&&hex.test(nonce)&&Number.isSafeInteger(now)&&Array.isArray(receipts)&&receipts.length>=3&&receipts.length<=4&&Array.isArray(trusted)&&trusted.length===4);
 const target=sha(JSON.stringify(candidate)),keys=new Map(),seen=new Set(),challenges=new Set();
 for(const t of trusted){
  const raw=Buffer.from(t.publicKey,'base64url');check(raw.length===44&&raw.toString('base64url')===t.publicKey&&sha(raw)===t.pin&&!keys.has(t.pin));
  const k=createPublicKey({key:raw,type:'spki',format:'der'});check(k.asymmetricKeyType==='ed25519');keys.set(t.pin,k);
 }
 for(const r of receipts){
  const raw=authBytes(r);
  check(keys.has(r.authorityPin)&&!seen.has(r.authorityPin)&&!challenges.has(r.challengeSha256)&&r.address===expected.address&&r.deviceId===expected.deviceId&&r.candidateDigest===target&&r.clientPin===clientPin&&r.nonce===nonce&&r.issuedAt<=now&&now<r.expires);
  const sig=Buffer.from(r.signature,'base64url');check(sig.length===64&&sig.toString('base64url')===r.signature&&verify(null,raw,keys.get(r.authorityPin),sig));
  seen.add(r.authorityPin);challenges.add(r.challengeSha256);
 }
 return Object.freeze({status:'fresh-native-authentication-quorum-lab',address:expected.address,deviceId:expected.deviceId,authorityCount:seen.size,nonce,labOnly:true,sessionAuthorized:false,mailPolicyActive:false});
}
