// Offline owner-side preparation of a NEW synthetic identity candidate.
// Never a relay endpoint, a registration or a device-private-key import.
import {createHash,createPublicKey,sign} from 'node:crypto';
import {canonicalManifestText} from './manifest-core.mjs';
import {fingerprintPublicKeyNode,deviceIdForPublicKeyNode,assertVerifiedManifest} from './manifest-node.mjs';
import {canonicalCryptoProfileText} from './crypto-profile-core.mjs';
import {verifyCryptoProfile} from './crypto-profile-node.mjs';
import {bindNativeContact} from './native-identity-bridge.mjs';
const fail=()=>{throw Error('Native identity candidate refused');};
const check=x=>{if(!x)fail();};
const sha=b=>createHash('sha256').update(b).digest('hex');
const spki=k=>k.export({type:'spki',format:'der'});
const hex=/^[a-f0-9]{64}$/;
const handleRE=/^[a-z0-9][a-z0-9._-]{2,31}$/;
function exact(o,fields){check(o&&typeof o==='object'&&!Array.isArray(o)&&Object.keys(o).length===fields.length&&fields.every(k=>Object.hasOwn(o,k)));}
function b64(s,n){check(typeof s==='string'&&s.length<=Math.ceil(n*4/3)&&/^[A-Za-z0-9_-]+$/.test(s));const b=Buffer.from(s,'base64url');check(b.length===n&&b.toString('base64url')===s);return b;}
function ecPoint(encoded){
 const b=b64(encoded,65);check(b[0]===4);
 const j={kty:'EC',crv:'P-256',x:b.subarray(1,33).toString('base64url'),y:b.subarray(33).toString('base64url')};
 const k=createPublicKey({key:j,format:'jwk'});check(k.asymmetricKeyDetails?.namedCurve==='prime256v1');
 return {j,pin:sha(spki(k))};
}
function pqPoint(encoded,type,n){
 const raw=b64(encoded,n),k=createPublicKey({key:raw,format:'der',type:'spki'});
 check(k.asymmetricKeyType===type&&spki(k).equals(raw));return {encoded,pin:sha(raw)};
}
const sig=(key,text)=>sign('sha256',Buffer.from(text,'utf8'),{key,dsaEncoding:'ieee-p1363'}).toString('base64');
export function nativeOwnerAddress(handle,ownerPublicKey){
 check(typeof handle==='string'&&handleRE.test(handle)&&ownerPublicKey?.type==='public'&&ownerPublicKey.asymmetricKeyType==='ec'&&ownerPublicKey.asymmetricKeyDetails?.namedCurve==='prime256v1');
 return handle+'~'+fingerprintPublicKeyNode(ownerPublicKey.export({format:'jwk'}),32)+'@quantic';
}
// The expected pin record MUST be independently authenticated by the owner.
// Neither an untrusted device record nor the relay can approve its own keys.
export function prepareNativeIdentityCandidate({labOnly,handle,record,expected,ownerSigning,ownerPQ,now=Date.now()}){
 check(labOnly===true&&handleRE.test(handle)&&Number.isSafeInteger(now)&&now>0);
 exact(expected,['address','deviceId','rootPin','pqRootPin','quorumPin','signingPin','encryptionPin','kemPin','dsaPin','controllerPublic']);
 const pins=['rootPin','pqRootPin','quorumPin','signingPin','encryptionPin','kemPin','dsaPin'];
 check(pins.every(k=>typeof expected[k]==='string'&&hex.test(expected[k])));
 check(ownerSigning?.type==='private'&&ownerSigning.asymmetricKeyType==='ec'&&ownerSigning.asymmetricKeyDetails?.namedCurve==='prime256v1');
 check(ownerPQ?.type==='private'&&ownerPQ.asymmetricKeyType==='ml-dsa-65');
 const owner=createPublicKey(ownerSigning),pqRoot=createPublicKey(ownerPQ);
 const address=nativeOwnerAddress(handle,owner);
 check(address===expected.address&&sha(spki(owner))===expected.rootPin&&sha(spki(pqRoot))===expected.pqRootPin);
 exact(record,['backend','address','deviceId','signingPin','encryptionPin','kemPin','dsaPin','signing','encryption','kemPublic','dsaPublic','status','controllerPublic','quorumPin','localReadback']);
 check(record.backend==='windows-software-pq-storage-lab'&&record.status==='local-provision-only-not-enrolled'&&record.localReadback==='verified');
 for(const k of ['address','deviceId','quorumPin','signingPin','encryptionPin','kemPin','dsaPin','controllerPublic'])check(record[k]===expected[k]);
 b64(record.controllerPublic,32);
 const s=ecPoint(record.signing),e=ecPoint(record.encryption),kem=pqPoint(record.kemPublic,'ml-kem-768',1206),dsa=pqPoint(record.dsaPublic,'ml-dsa-65',1974);
 check(s.pin===expected.signingPin&&e.pin===expected.encryptionPin&&kem.pin===expected.kemPin&&dsa.pin===expected.dsaPin);
 // Distinct ownership and device signing keys. Do not silently turn the
 // existing device key into the ownership root.
 check(new Set([expected.rootPin,expected.pqRootPin,s.pin,e.pin,kem.pin,dsa.pin]).size===6);
 check(deviceIdForPublicKeyNode(e.j,32)===expected.deviceId);
 const ownerJwk=owner.export({format:'jwk'}),issuedAt=new Date(now).toISOString();
 const m={version:1,sequence:1,canonicalAddress:address,handle,fingerprint:fingerprintPublicKeyNode(ownerJwk,32),identityPublicKey:e.j,identitySigningPublicKey:ownerJwk,devices:[{deviceId:expected.deviceId,label:'Native Windows lab',publicKey:e.j,deviceSigningPublicKey:s.j,kind:'root',issuedAt}],revocations:[],issuedAt};
 const manifest={format:'quantic-identity-manifest',version:1,payload:m,signature:sig(ownerSigning,canonicalManifestText(m))};
 const q={version:2,sequence:1,canonicalAddress:address,identitySigningPublicKey:ownerJwk,identityManifestSequence:1,policy:'hybrid-required',identityMlDsaAlgorithm:'ML-DSA-65',identityMlDsaPublicKeySpki:spki(pqRoot).toString('base64url'),devices:[{deviceId:expected.deviceId,mlKemAlgorithm:'ML-KEM-768',mlKemPublicKeySpki:kem.encoded,mlDsaAlgorithm:'ML-DSA-65',mlDsaPublicKeySpki:dsa.encoded}],issuedAt};
 const raw=canonicalCryptoProfileText(q);
 const profile={format:'quantic-crypto-profile',version:2,payload:q,signatures:{p256:sig(ownerSigning,raw),mlDsa65Self:sign(null,Buffer.from(raw,'utf8'),ownerPQ).toString('base64url')}};
 assertVerifiedManifest(manifest);verifyCryptoProfile(profile,manifest);
 const policyCandidate={address,deviceId:expected.deviceId,rootPin:expected.rootPin,pqRootPin:expected.pqRootPin,manifestSequence:1,profileSequence:1,manifestDigest:sha(canonicalManifestText(m)),profileDigest:sha(raw),active:false};
 // Verify the exact bundle through the existing native mail bridge. This is
 // deliberately NOT an active authority checkpoint or proof of possession.
 bindNativeContact({manifest,profile},{...policyCandidate,expires:now+10000},now);
 return {format:'quantic-native-owner-candidate-lab/v1',labOnly:true,bundle:{manifest,profile},policyCandidate,
  devicePossessionVerified:false,registrationAuthorized:false,legacyDeletionAuthorized:false};
}
