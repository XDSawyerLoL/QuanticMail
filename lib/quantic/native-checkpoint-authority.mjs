// Independent checkpoint attestation, using the existing durable relay snapshot.
import {createHash,createPublicKey,sign,verify} from 'node:crypto';
import {bindNativeContact,verifyNativeWire} from './native-identity-bridge.mjs';
const check=v=>{if(!v)throw Error('Native authority checkpoint refused');};
const hex=/^[a-f0-9]{64}$/;
const addr=/^[a-z0-9][a-z0-9._-]{2,31}~[a-f0-9]{32}@quantic$/;
const dev=/^d-[a-f0-9]{32}$/;
const fields=['address','deviceId','rootPin','pqRootPin','manifestSequence','profileSequence','manifestDigest','profileDigest'];
const hash=b=>createHash('sha256').update(b).digest('hex');
export const CHECKPOINT_TTL=15000;
function keyPin(key){return hash(key.export({type:'spki',format:'der'}));}
function parseKey(encoded){
 check(typeof encoded==='string'&&/^[A-Za-z0-9_-]{59}$/.test(encoded));
 const der=Buffer.from(encoded,'base64url');check(der.length===44&&der.toString('base64url')===encoded);
 const key=createPublicKey({key:der,format:'der',type:'spki'});check(key.asymmetricKeyType==='ed25519');return key;
}
function guardCheckpoint(p){
 check(p&&Object.keys(p).length===10&&fields.every(k=>Object.hasOwn(p,k))&&addr.test(p.address)&&dev.test(p.deviceId));
 check(['rootPin','pqRootPin','manifestDigest','profileDigest','nonce'].every(k=>typeof p[k]==='string'&&hex.test(p[k])));
 check(['manifestSequence','profileSequence','expires'].every(k=>Number.isSafeInteger(p[k])&&p[k]>0));
}
function canonical(p){
 guardCheckpoint(p);
 return Buffer.from(JSON.stringify(['quantic-native-checkpoint-authority/v1',...fields.map(k=>p[k]),p.nonce,p.expires]));
}
function exactPair(entries,address){
 check(Array.isArray(entries)&&entries.length<=100000);
 const matches=entries.filter(x=>Array.isArray(x)&&x.length===2&&x[0]===address);
 check(matches.length===1);return matches[0][1];
}
export function issueCheckpoint({state,policy,request,privateKey,now=Date.now()}){
 // The policy is independently maintained, not inferred from relay state.
 check(state?.format==='quantic-relay-state'&&state.version===3&&Number.isSafeInteger(now));
 const saved=Date.parse(state.savedAt);check(Number.isFinite(saved)&&saved<=now&&saved>now-30000);
 check(Array.isArray(policy)&&policy.length>=1&&policy.length<=1024);
 check(request&&addr.test(request.address)&&dev.test(request.deviceId)&&hex.test(request.nonce)&&Number.isSafeInteger(request.expires)&&request.expires>now&&request.expires<=now+CHECKPOINT_TTL);
 const matches=policy.filter(p=>p.address===request.address&&p.deviceId===request.deviceId);
 check(matches.length===1);
 const p=matches[0];check(p.active===true);
 const payload=Object.fromEntries(fields.map(k=>[k,p[k]]));
 payload.nonce=request.nonce;payload.expires=request.expires;
 const bundle={manifest:exactPair(state.manifests,request.address),profile:exactPair(state.cryptoProfiles,request.address)};
 bindNativeContact(bundle,payload,now);
 check(privateKey?.type==='private'&&privateKey.asymmetricKeyType==='ed25519');
 const pub=createPublicKey(privateKey);
 return {bundle,attestation:{authorityPin:keyPin(pub),payload,signature:sign(null,canonical(payload),privateKey).toString('base64url')}};
}
export function verifyCheckpointQuorum(attestations,trusted,request,now=Date.now()){
 check(Array.isArray(trusted)&&trusted.length===4&&Array.isArray(attestations)&&attestations.length<=4&&Number.isSafeInteger(now));
 check(request&&addr.test(request.address)&&dev.test(request.deviceId)&&hex.test(request.nonce)&&Number.isSafeInteger(request.expires)&&request.expires>now&&request.expires<=now+CHECKPOINT_TTL);
 const keys=new Map();
 for(const t of trusted){
  const key=parseKey(t.publicKey);check(hex.test(t.pin)&&keyPin(key)===t.pin&&!keys.has(t.pin));keys.set(t.pin,key);
 }
 const seen=new Set(),groups=new Map();
 for(const a of attestations){
  try{
   check(a&&keys.has(a.authorityPin)&&!seen.has(a.authorityPin));
   const p=a.payload;const bytes=canonical(p);
   check(p.address===request.address&&p.deviceId===request.deviceId&&p.nonce===request.nonce&&p.expires===request.expires);
   check(typeof a.signature==='string'&&/^[A-Za-z0-9_-]{86}$/.test(a.signature));
   const sig=Buffer.from(a.signature,'base64url');check(sig.toString('base64url')===a.signature&&verify(null,bytes,keys.get(a.authorityPin),sig));
   seen.add(a.authorityPin);
   const d=hash(bytes),g=groups.get(d)??{count:0,p};g.count++;groups.set(d,g);
  }catch{/* A bad vote cannot contribute to the quorum. */}
 }
 const chosen=[...groups.values()].find(g=>g.count>=3);check(chosen);
 const p=chosen.p;
 // Return only the bridge's checkpoint fields, never a network-supplied root.
 return Object.freeze({...Object.fromEntries(fields.map(k=>[k,p[k]])),expires:p.expires});
}
export function verifyAttestedNativeWire(record,sender,recipient,trusted,senderRequest,recipientRequest,now=Date.now()){
 const a=verifyCheckpointQuorum(sender.attestations,trusted,senderRequest,now);
 const b=verifyCheckpointQuorum(recipient.attestations,trusted,recipientRequest,now);
 return verifyNativeWire(record,sender.bundle,a,recipient.bundle,b,now);
}
