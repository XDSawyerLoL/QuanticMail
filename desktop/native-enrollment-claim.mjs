// Public operator-side verification only. No private keys, enrollment, network,
// authority grant or file mutation. Trust anchors are obtained independently.
import {createHash,createPublicKey,verify} from 'node:crypto';
import {assertVerifiedManifest,deviceIdForPublicKeyNode} from '../lib/quantic/manifest-node.mjs';
import {verifyCryptoProfile} from '../lib/quantic/crypto-profile-node.mjs';
import {canonicalManifestText} from '../lib/quantic/manifest-core.mjs';
import {canonicalCryptoProfileText} from '../lib/quantic/crypto-profile-core.mjs';
const check=x=>{if(!x)throw Error('Native enrollment claim refused');};
const hash=x=>createHash('sha256').update(x).digest('hex');
const pin=/^[a-f0-9]{64}$/;
const spki=k=>k.export({type:'spki',format:'der'});
const ec=j=>createPublicKey({key:j,format:'jwk'});
function bytes(s,encoding,n){
 check(typeof s==='string'&&s.length<=Math.ceil(n/3)*4);
 const b=Buffer.from(s,encoding);check(b.length===n&&b.toString(encoding)===s);return b;
}
function pq(s,kind,n){
 const b=bytes(s,'base64url',n),k=createPublicKey({key:b,type:'spki',format:'der'});
 check(k.asymmetricKeyType===kind&&spki(k).equals(b));return k;
}
export function verifyNativeEnrollmentRequest(r,{quorumPin,now=Date.now()}={}){
 check(pin.test(quorumPin??'')&&r?.format==='quantic-native-enrollment-request-lab/v1'&&r.quorumPin===quorumPin);
 bytes(r.controllerPublic,'base64url',32);
 const c=r.claim;
 check(c?.format==='quantic-native-enrollment-claim-lab/v1'&&c.version===1&&c.labOnly===true&&
  c.status==='signed-claim-not-enrolled'&&c.mailAuthorized===false&&c.remotelyEnrolled===false);
 const m=assertVerifiedManifest(c.manifest),p=verifyCryptoProfile(c.profile,m),mp=m.payload,pp=p.payload;
 check(mp.sequence===1&&pp.sequence===1&&mp.devices.length===1&&pp.devices.length===1&&mp.revocations.length===0&&pp.policy==='hybrid-required'&&pp.identityManifestSequence===1);
 const d=mp.devices[0],pd=pp.devices[0];
 check(c.address===mp.canonicalAddress&&c.address===pp.canonicalAddress&&c.deviceId===d.deviceId&&c.deviceId===pd.deviceId&&d.kind==='root'&&deviceIdForPublicKeyNode(d.publicKey,32)===c.deviceId);
 const stamp=Date.parse(mp.issuedAt);
 check(Number.isSafeInteger(now)&&Number.isFinite(stamp)&&stamp<=now+300000&&stamp>=now-86400000&&pp.issuedAt===mp.issuedAt&&d.issuedAt===mp.issuedAt);
 const owner=ec(mp.identitySigningPublicKey),root=pq(pp.identityMlDsaPublicKeySpki,'ml-dsa-65',1974);
 const keys={rootPin:hash(spki(owner)),pqRootPin:hash(spki(root)),
  signingPin:hash(spki(ec(d.deviceSigningPublicKey))),encryptionPin:hash(spki(ec(d.publicKey))),
  kemPin:hash(spki(pq(pd.mlKemPublicKeySpki,'ml-kem-768',1206))),dsaPin:hash(spki(pq(pd.mlDsaPublicKeySpki,'ml-dsa-65',1974))),
  manifestDigest:hash(canonicalManifestText(mp)),profileDigest:hash(canonicalCryptoProfileText(pp))};
 check(Object.entries(keys).every(([k,v])=>c[k]===v)&&new Set([keys.rootPin,keys.signingPin,keys.encryptionPin]).size===3&&keys.pqRootPin!==keys.dsaPin);
 check(hash(spki(ec(mp.identityPublicKey)))===keys.encryptionPin);
 const transcript=Buffer.from(JSON.stringify([r.format,c.address,c.deviceId,c.rootPin,c.pqRootPin,c.manifestDigest,c.profileDigest,r.quorumPin,r.controllerPublic]));
 check(verify('sha256',transcript,{key:owner,dsaEncoding:'ieee-p1363'},bytes(r.ownerP256Signature,'base64',64)));
 check(verify(null,transcript,root,bytes(r.ownerMlDsaSignature,'base64url',3309)));
 return Object.freeze({status:'valid-public-claim-pending-independent-approval',labOnly:true,address:c.address,deviceId:c.deviceId,
  ...keys,quorumPin:r.quorumPin,remotelyEnrolled:false,mailAuthorized:false});
}
