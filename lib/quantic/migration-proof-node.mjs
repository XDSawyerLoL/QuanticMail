// Trusted local Node 24 only. No writes, network, registration or migration authorization.
import {createHash,createPrivateKey,createPublicKey,diffieHellman,generateKeyPairSync,randomBytes,sign,verify} from 'node:crypto';
import {openMigrationArchive,migrationArchiveSummary} from './migration-archive.ts';
import {assertVerifiedManifest,deviceIdForPublicKeyNode} from './manifest-node.mjs';
import {identityNamesForKey} from './identity-names.mjs';
import {verifyPreKeySignature} from './prekey-core.mjs';
import {encryptForRecipientCore,decryptEnvelopeCore} from './envelope-crypto.mjs';
import {mlKemEncapsulate,mlKemDecapsulate,mlDsaSign,mlDsaVerify} from './pqc-runtime-node.ts';
const refuse=ok=>{if(!ok)throw Error('Historical identity recovery verification refused');};
function publicEC(j){
 refuse(j?.kty==='EC'&&j.crv==='P-256'&&!('d' in j));
 for(const v of [j.x,j.y])refuse(typeof v==='string'&&/^[A-Za-z0-9_-]{43}$/.test(v)&&Buffer.from(v,'base64url').toString('base64url')===v);
 const key=createPublicKey({key:{kty:'EC',crv:'P-256',x:j.x,y:j.y},format:'jwk'});
 refuse(key.asymmetricKeyType==='ec'&&key.asymmetricKeyDetails.namedCurve==='prime256v1');return key;
}
const pubDigest=j=>createHash('sha256').update(publicEC(j).export({type:'spki',format:'der'})).digest('hex');
function secretEC(j){
 refuse(j?.kty==='EC'&&j.crv==='P-256'&&typeof j.d==='string'&&/^[A-Za-z0-9_-]{43}$/.test(j.d)&&Buffer.from(j.d,'base64url').toString('base64url')===j.d);
 return createPrivateKey({key:{kty:'EC',crv:'P-256',x:j.x,y:j.y,d:j.d},format:'jwk'});
}
function proveSigning(pub,priv){
 const challenge=randomBytes(32),p=publicEC(pub),k=secretEC(priv);
 refuse(verify('sha256',challenge,p,sign('sha256',challenge,k)));
}
function proveAgreement(pub,priv){
 const e=generateKeyPairSync('ec',{namedCurve:'prime256v1'});let a,b;
 try{a=diffieHellman({privateKey:e.privateKey,publicKey:publicEC(pub)});b=diffieHellman({privateKey:secretEC(priv),publicKey:e.publicKey});refuse(a.length===32&&a.equals(b));}
 finally{a?.fill(0);b?.fill(0);}
}
// Exercise the actual legacy envelope cipher, not just ECDH key equality.
async function proveLegacyDecryption(pub,priv){
 const challenge=randomBytes(32).toString('hex');
 const fixture=await encryptForRecipientCore(pub,{challenge});
 const result=await decryptEnvelopeCore(priv,fixture);
 refuse(result?.challenge===challenge&&Object.keys(result).length===1);
}
function provePQ(p){
 if(p===undefined)return false;
 refuse(p&&p.version===1);
 for(const k of ['mlKemPublicKeySpki','mlKemPrivateKeyPkcs8','mlDsaPublicKeySpki','mlDsaPrivateKeyPkcs8']){
  const v=p[k];refuse(typeof v==='string'&&v.length>=32&&v.length<=32768&&/^[A-Za-z0-9_-]+$/.test(v)&&Buffer.from(v,'base64url').toString('base64url')===v);
 }
 const c=mlKemEncapsulate(p.mlKemPublicKeySpki);let opened;
 try{opened=mlKemDecapsulate(p.mlKemPrivateKeyPkcs8,c.ciphertext);refuse(opened.length===32&&opened.equals(c.sharedSecret));}
 finally{opened?.fill(0);c.sharedSecret.fill(0);}
 const challenge=randomBytes(32),signature=mlDsaSign(p.mlDsaPrivateKeyPkcs8,challenge);refuse(mlDsaVerify(p.mlDsaPublicKeySpki,challenge,signature));return true;
}
export async function verifyMigrationArchiveOffline(text,password,{expectedAddress,trustedRootPin}){
 // Pin is SHA-256 of original root signing SPKI obtained independently of this archive.
 refuse(typeof trustedRootPin==='string'&&/^[a-f0-9]{64}$/.test(trustedRootPin));
 const a=await openMigrationArchive(text,password,expectedAddress),i=a.identity;
 const summary=migrationArchiveSummary(a);
 refuse(i.role==='root'||i.role==='secondary');
 refuse(pubDigest(i.signingPublicKey)===trustedRootPin);
 const names=identityNamesForKey(i.handle,i.signingPublicKey,i.fingerprint);
 refuse(names.canonicalAddress===expectedAddress&&i.canonicalAddress===expectedAddress);
 // A historical signed manifest does not establish freshness or live device permission.
 const m=assertVerifiedManifest(i.manifest).payload;
 refuse(m.canonicalAddress===expectedAddress&&pubDigest(m.identitySigningPublicKey)===trustedRootPin);
 const device=m.devices.find(d=>d.deviceId===i.deviceId);
 refuse(device&&device.kind===(i.role==='root'?'root':'linked')&&pubDigest(device.publicKey)===pubDigest(i.publicKey)&&pubDigest(device.deviceSigningPublicKey)===pubDigest(i.deviceSigningPublicKey));
 const n=i.deviceId.length-2;refuse((n===10||n===32)&&deviceIdForPublicKeyNode(i.publicKey,n)===i.deviceId);
 if(i.role==='root')proveSigning(i.signingPublicKey,i.signingPrivateKey);
 else refuse(i.signingPrivateKey===undefined);
 proveAgreement(i.publicKey,i.privateKey);proveSigning(i.deviceSigningPublicKey,i.deviceSigningPrivateKey);
 await proveLegacyDecryption(i.publicKey,i.privateKey);
 const pq=provePQ(i.pqc),ids=new Set();
 for(const p of a.prekeys){
  refuse(p?.version===1&&p.canonicalAddress===expectedAddress&&p.deviceId===i.deviceId&&typeof p.preKeyId==='string'&&p.preKeyId.length>=1&&p.preKeyId.length<=128&&!ids.has(p.preKeyId)&&['claimed','unused'].includes(p.state));
  // Expired and claimed prekeys remain historical only. Signature must bind their exact original scope.
  refuse(await verifyPreKeySignature(p,i.deviceSigningPublicKey));
  ids.add(p.preKeyId);proveAgreement(p.publicKey,p.privateKey);await proveLegacyDecryption(p.publicKey,p.privateKey);
 }
 // Pending credentials must never be silently promoted to an active device.
 if(a.pending){
  const p=a.pending;refuse(p.canonicalAddress===expectedAddress&&typeof p.deviceId==='string');
  const len=p.deviceId.length-2;refuse((len===10||len===32)&&deviceIdForPublicKeyNode(p.publicKey,len)===p.deviceId);
  proveAgreement(p.publicKey,p.privateKey);proveSigning(p.deviceSigningPublicKey,p.deviceSigningPrivateKey);provePQ(p.pqc);
 }
 return Object.freeze({historicalRootPinVerified:true,historicalManifestSequence:m.sequence,deviceKeyPossessionVerified:true,rootPrivateKeyVerified:i.role==='root',prekeyPairsVerified:ids.size,historicalPrekeySignaturesVerified:ids.size,syntheticLegacyEnvelopeRecoveryVerified:true,postQuantumKeyPairsVerified:pq,pendingRequiresResolution:!!a.pending,counts:summary,liveRestoreAuthorized:false,legacyDeletionAuthorized:false,blockers:Object.freeze(['fresh-authority-checkpoint-required','native-device-enrollment-required','historical-message-recovery-required','atomic-cutover-required',...(pq?[]:['post-quantum-enrollment-required']),...(a.pending?['pending-device-must-be-resolved']:[])])});
}
