// Trusted local Node 24 adapter. No enrollment, network lookup or private key access.
// The checkpoint argument MUST originate from an independently authenticated
// current authority, never the untrusted bundle or incoming message.
import {createHash,createPublicKey,verify} from 'node:crypto';
import {assertVerifiedManifest,deviceIdForPublicKeyNode} from './manifest-node.mjs';
import {canonicalManifestText,activeDevices} from './manifest-core.mjs';
import {verifyCryptoProfile} from './crypto-profile-node.mjs';
import {canonicalCryptoProfileText} from './crypto-profile-core.mjs';
const sha=b=>createHash('sha256').update(b).digest('hex');
const check=(x)=>{if(!x)throw Error('Native Quantic ID binding refused');};
const address=/^[a-z0-9][a-z0-9._-]{2,31}~[a-f0-9]{32}@quantic$/;
const device=/^d-[a-f0-9]{32}$/;
const hex=/^[a-f0-9]{64}$/;
const msg=/^[A-Za-z0-9._:-]{8,128}$/;
const suite='QNT-HYB-P256-MLKEM768-HKDFSHA256-AES256GCM-1';
function b64(s,min,max){
 check(typeof s==='string'&&s.length<=Math.ceil(max/3)*4&&/^[A-Za-z0-9_-]+$/.test(s));
 const b=Buffer.from(s,'base64url');check(b.length>=min&&b.length<=max&&b.toString('base64url')===s);return b;
}
function ec(j){
 check(j?.kty==='EC'&&j.crv==='P-256'&&!Object.hasOwn(j,'d'));
 b64(j.x,32,32);b64(j.y,32,32);
 const k=createPublicKey({key:j,format:'jwk'});check(k.asymmetricKeyDetails?.namedCurve==='prime256v1');return k;
}
function spki(k){return k.export({type:'spki',format:'der'});}
function pq(s,type,size){
 const raw=b64(s,size,size),key=createPublicKey({key:raw,type:'spki',format:'der'});
 check(key.asymmetricKeyType===type&&spki(key).equals(raw));return key;
}
export function bindNativeContact(bundle,checkpoint,now=Date.now()){
 check(bundle&&checkpoint&&Number.isSafeInteger(now)&&Number.isSafeInteger(checkpoint.expires)&&checkpoint.expires>now&&checkpoint.expires<=now+30000);
 for(const p of ['rootPin','pqRootPin','manifestDigest','profileDigest'])check(typeof checkpoint[p]==='string'&&hex.test(checkpoint[p]));
 check(address.test(checkpoint.address)&&device.test(checkpoint.deviceId));
 const m=assertVerifiedManifest(bundle.manifest);
 const p=verifyCryptoProfile(bundle.profile,m);
 check(m.payload.canonicalAddress===checkpoint.address&&p.payload.canonicalAddress===checkpoint.address);
 check(m.payload.sequence===checkpoint.manifestSequence&&p.payload.sequence===checkpoint.profileSequence&&p.payload.identityManifestSequence===m.payload.sequence&&p.payload.policy==='hybrid-required');
 check(sha(canonicalManifestText(m.payload))===checkpoint.manifestDigest&&sha(canonicalCryptoProfileText(p.payload))===checkpoint.profileDigest);
 check(sha(spki(ec(m.payload.identitySigningPublicKey)))===checkpoint.rootPin);
 check(sha(spki(pq(p.payload.identityMlDsaPublicKeySpki,'ml-dsa-65',1974)))===checkpoint.pqRootPin);
 const d=activeDevices(m).find(x=>x.deviceId===checkpoint.deviceId),pd=p.payload.devices.find(x=>x.deviceId===checkpoint.deviceId);
 check(d&&pd&&deviceIdForPublicKeyNode(d.publicKey,32)===checkpoint.deviceId);
 const sk=ec(d.deviceSigningPublicKey),ek=ec(d.publicKey),dk=pq(pd.mlDsaPublicKeySpki,'ml-dsa-65',1974),kk=pq(pd.mlKemPublicKeySpki,'ml-kem-768',1206);
 const contact=Object.freeze({address:checkpoint.address,deviceId:checkpoint.deviceId,classicalSigningSpki:spki(sk).toString('base64'),mlDsaSigningSpki:spki(dk).toString('base64'),classicalEncryptionSpki:spki(ek).toString('base64'),mlKemEncryptionSpki:spki(kk).toString('base64'),expires:checkpoint.expires});
 return contact;
}
export function nativeSenderTranscript(c,e){
 check(c&&e&&address.test(c.from)&&address.test(c.to)&&device.test(c.fromDeviceId)&&device.test(c.toDeviceId)&&typeof c.clientMessageId==='string'&&msg.test(c.clientMessageId));
 check(e.cryptoSuite===suite&&e.keyMode==='hybrid-static-fallback');
 const j=e.classicalEphemeralPublicKey;ec(j);check(!j.key_ops||Array.isArray(j.key_ops)&&j.key_ops.length===0);
 b64(e.pqKemCiphertext,1088,1088);b64(e.iv,12,12);b64(e.ciphertext,17,8208);
 return Buffer.from(JSON.stringify(['quantic-mail-sender-auth-lab/v1',c.clientMessageId,c.from,c.fromDeviceId,c.to,c.toDeviceId,e.cryptoSuite,e.keyMode,j.kty,j.crv,j.x,j.y,e.pqKemCiphertext,e.iv,e.ciphertext]));
}
// Verify both peers against independently supplied checkpoints. Not a relay
// authorization: no claim about fresh quorum or contact permission issuance.
export function verifyNativeWire(record,senderBundle,senderCheckpoint,recipientBundle,recipientCheckpoint,now=Date.now()){
 check(record?.format==='quantic-native-mail'&&record.version===1);
 const c=record.context,e=record.envelope,a=record.senderAuth;
 const from=bindNativeContact(senderBundle,senderCheckpoint,now),to=bindNativeContact(recipientBundle,recipientCheckpoint,now);
 check(c?.from===from.address&&c.fromDeviceId===from.deviceId&&c.to===to.address&&c.toDeviceId===to.deviceId);
 const raw=nativeSenderTranscript(c,e);
 const sk=createPublicKey({key:Buffer.from(from.classicalSigningSpki,'base64'),type:'spki',format:'der'});
 const dk=createPublicKey({key:Buffer.from(from.mlDsaSigningSpki,'base64'),type:'spki',format:'der'});
 check(verify('sha256',raw,{key:sk,dsaEncoding:'ieee-p1363'},b64(a?.classicalSignature,64,64)));
 check(verify(null,raw,dk,b64(a?.pqSignature,3309,3309)));
 return Object.freeze({verified:true,from:from.address,fromDeviceId:from.deviceId,to:to.address,toDeviceId:to.deviceId,clientMessageId:c.clientMessageId,transcriptSha256:sha(raw),liveDeliveryAuthorized:false});
}
