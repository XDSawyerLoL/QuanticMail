// Offline recovery self-test. Only a trusted local process may call this module.
// Does not authorize live keys or expose a signing/decapsulation oracle.
import {createHash,createPrivateKey,createPublicKey,randomBytes,timingSafeEqual} from "node:crypto";
import {openMigrationArchive} from "../lib/quantic/migration-archive.ts";
import {detectPqcCapabilities,mlKemEncapsulate,mlKemDecapsulate,mlDsaSign,mlDsaVerify} from "../lib/quantic/pqc-runtime-node.ts";
import {decryptHybridEnvelopeNode,type HybridEnvelopeContext,type HybridEncryptedEnvelope} from "../lib/quantic/hybrid-envelope-node.ts";
const sha=(data:Uint8Array)=>createHash("sha256").update(data).digest("hex");
const check=(ok:unknown):void=>{if(!ok)throw Error("Offline PQ recovery refused.");};
export type RecoveryPins={canonicalAddress:string;deviceId:string;rootSigningSpki:string;encryptionSpki:string;mlKemSpki:string;mlDsaSpki:string};
export type HistoricalFixture={context:HybridEnvelopeContext;envelope:HybridEncryptedEnvelope;expectedPlaintextSha256:string};
function keyPin(publicKey:ReturnType<typeof createPublicKey>){return sha(publicKey.export({type:"spki",format:"der"}));}
function strictDer(value:string,max:number){
 check(typeof value==="string"&&value.length<=Math.ceil(max/3)*4&&/^[A-Za-z0-9_-]+$/.test(value));
 const bytes=Buffer.from(value,"base64url");check(bytes.length>0&&bytes.length<=max&&bytes.toString("base64url")===value);return bytes;
}
function classical(j:JsonWebKey){
 check(j?.kty==="EC"&&j.crv==="P-256"&&typeof j.x==="string"&&typeof j.y==="string"&&!Object.hasOwn(j,"d"));
 const p=createPublicKey({key:j,format:"jwk"});check(p.asymmetricKeyDetails?.namedCurve==="prime256v1");return p;
}
function verifyPqPair(pub:string,priv:string,algorithm:"ml-kem-768"|"ml-dsa-65",pin:string){
 const publicKey=createPublicKey({key:strictDer(pub,8192),format:"der",type:"spki"});
 const raw=strictDer(priv,16384);
 try{
  const secret=createPrivateKey({key:raw,format:"der",type:"pkcs8"});
  check(secret.asymmetricKeyType===algorithm&&publicKey.asymmetricKeyType===algorithm&&keyPin(publicKey)===pin&&keyPin(createPublicKey(secret))===pin);
 }finally{raw.fill(0);}
}
export async function verifyOfflinePqRecovery(text:string,password:string,pins:RecoveryPins,fixture?:HistoricalFixture){
 const caps=detectPqcCapabilities();
 check(caps.mlKem768&&caps.mlDsa65);
 check(pins&&typeof pins.canonicalAddress==="string"&&/^d-[a-f0-9]{32}$/.test(pins.deviceId));
 for(const pin of [pins.rootSigningSpki,pins.encryptionSpki,pins.mlKemSpki,pins.mlDsaSpki])check(typeof pin==="string"&&/^[a-f0-9]{64}$/.test(pin));
 const a=await openMigrationArchive(text,password,pins.canonicalAddress),i=a.identity;
 const root=classical(i.signingPublicKey!);
 const enc=classical(i.publicKey);
 const fingerprint=sha(Buffer.from("P-256:"+i.signingPublicKey!.x+":"+i.signingPublicKey!.y));
 check(pins.canonicalAddress===i.handle+"~"+fingerprint.slice(0,32)+"@quantic");
 check(i.deviceId===pins.deviceId&&pins.deviceId==="d-"+sha(Buffer.from("P-256:"+i.publicKey.x+":"+i.publicKey.y)).slice(0,32));
 check(keyPin(root)===pins.rootSigningSpki&&keyPin(enc)===pins.encryptionSpki);
 check(i.privateKey?.kty==="EC"&&i.privateKey.crv==="P-256"&&keyPin(createPublicKey(createPrivateKey({key:i.privateKey,format:"jwk"})))===pins.encryptionSpki);
 const pq=i.pqc;
 if(!pq||pq.version!==1)throw Error("Offline PQ recovery refused.");
 verifyPqPair(pq.mlKemPublicKeySpki,pq.mlKemPrivateKeyPkcs8,"ml-kem-768",pins.mlKemSpki);
 verifyPqPair(pq.mlDsaPublicKeySpki,pq.mlDsaPrivateKeyPkcs8,"ml-dsa-65",pins.mlDsaSpki);
 const trial=mlKemEncapsulate(pq.mlKemPublicKeySpki);
 let recovered:Buffer|undefined;
 try{recovered=mlKemDecapsulate(pq.mlKemPrivateKeyPkcs8,trial.ciphertext);
 check(recovered.length===32&&trial.sharedSecret.length===32&&timingSafeEqual(recovered,trial.sharedSecret));}
 finally{recovered?.fill(0);trial.sharedSecret.fill(0);}
 const challenge=Buffer.concat([Buffer.from("quantic-offline-recovery-self-test-v1\0"),randomBytes(32)]);
 const signature=mlDsaSign(pq.mlDsaPrivateKeyPkcs8,challenge);
 check(mlDsaVerify(pq.mlDsaPublicKeySpki,challenge,signature));
 let historicalHybridVerified=false;
 if(fixture){
  check(fixture.context?.to===pins.canonicalAddress&&fixture.context?.toDeviceId===pins.deviceId&&/^[a-f0-9]{64}$/.test(fixture.expectedPlaintextSha256));
  // Require independently recorded expected digest of JSON serialized payload.
  // Existing hybrid suite, no plaintext output or acknowledgement.
  const result=decryptHybridEnvelopeNode({recipientClassicalPrivateKey:i.privateKey,recipientMlKemPrivateKeyPkcs8:pq.mlKemPrivateKeyPkcs8,context:fixture.context,envelope:fixture.envelope});
  const bytes=Buffer.from(JSON.stringify(result));
  try{check(sha(bytes)===fixture.expectedPlaintextSha256);historicalHybridVerified=true;}finally{bytes.fill(0);}
 }
 return Object.freeze({mlKemVerified:true,mlDsaVerified:true,historicalHybridVerified,liveRestoreAuthorized:false,quorumVerified:false,safeToDeleteLegacyKeys:false});
}
