import test from "node:test";
import assert from "node:assert/strict";
import {createHash,generateKeyPairSync,createPublicKey} from "node:crypto";
import {prepareMigrationArchive,sealMigrationArchive} from "../lib/quantic/migration-archive.ts";
import {generateMlKem768KeyPair,generateMlDsa65KeyPair} from "../lib/quantic/pqc-runtime-node.ts";
import {encryptHybridEnvelopeNode} from "../lib/quantic/hybrid-envelope-node.ts";
import {verifyOfflinePqRecovery} from "../desktop/offline-pq-recovery.ts";
const sha=x=>createHash("sha256").update(x).digest("hex"),point=k=>k.publicKey.export({format:"jwk"}),pin=k=>sha(k.export({format:"der",type:"spki"})),id=j=>sha("P-256:"+j.x+":"+j.y).slice(0,32);
const password="synthetic offline recovery test passphrase";
async function fixture(){
 const root=generateKeyPairSync("ec",{namedCurve:"prime256v1"}),enc=generateKeyPairSync("ec",{namedCurve:"prime256v1"}),kem=generateMlKem768KeyPair(),dsa=generateMlDsa65KeyPair();
 const j=point(root),e=point(enc),address="alice~"+id(j)+"@quantic",deviceId="d-"+id(e);
 const identity={handle:"alice",canonicalAddress:address,deviceId,signingPublicKey:j,publicKey:e,privateKey:enc.privateKey.export({format:"jwk"}),authToken:"excluded",pqc:{version:1,mlKemPublicKeySpki:kem.publicKeySpki,mlKemPrivateKeyPkcs8:kem.privateKeyPkcs8,mlDsaPublicKeySpki:dsa.publicKeySpki,mlDsaPrivateKeyPkcs8:dsa.privateKeyPkcs8}};
 const pqPin=s=>pin(createPublicKey({key:Buffer.from(s,"base64url"),format:"der",type:"spki"}));
 const pins={canonicalAddress:address,deviceId,rootSigningSpki:pin(root.publicKey),encryptionSpki:pin(enc.publicKey),mlKemSpki:pqPin(kem.publicKeySpki),mlDsaSpki:pqPin(dsa.publicKeySpki)};
 const context={clientMessageId:"historical-synthetic-001",from:"bob~"+"a".repeat(32)+"@quantic",fromDeviceId:"d-"+"a".repeat(32),to:address,toDeviceId:deviceId};
 const payload={body:"historical synthetic message"},envelope=encryptHybridEnvelopeNode({recipientClassicalPublicKey:e,recipientMlKemPublicKeySpki:kem.publicKeySpki,context,payload});
 const seal=identity=>sealMigrationArchive(prepareMigrationArchive({identity,pending:null,prekeys:[],messages:[],outbox:[],contacts:[]}),password);
 return {identity,pins,seal,fixture:{context,envelope,expectedPlaintextSha256:sha(JSON.stringify(payload))},text:await seal(identity)};
}
test("offline recovery verifies real pinned PQ material and historical hybrid ciphertext",async()=>{
 const f=await fixture();
 const result=await verifyOfflinePqRecovery(f.text,password,f.pins,f.fixture);
 assert.deepEqual(result,{mlKemVerified:true,mlDsaVerified:true,historicalHybridVerified:true,liveRestoreAuthorized:false,quorumVerified:false,safeToDeleteLegacyKeys:false});
 assert.ok(!JSON.stringify(result).includes("synthetic message"));
});
test("pin mismatch and wrong historical digest fail closed",async()=>{
 const f=await fixture();
 for(const key of ["rootSigningSpki","encryptionSpki","mlKemSpki","mlDsaSpki"])await assert.rejects(verifyOfflinePqRecovery(f.text,password,{...f.pins,[key]:"0".repeat(64)}));
 await assert.rejects(verifyOfflinePqRecovery(f.text,password,f.pins,{...f.fixture,expectedPlaintextSha256:"0".repeat(64)}));
 await assert.rejects(verifyOfflinePqRecovery(f.text,password,f.pins,{...f.fixture,context:{...f.fixture.context,toDeviceId:"d-"+"a".repeat(32)}}));
});
test("archive containing an unrelated PQ private key is rejected even with valid AEAD",async()=>{
 const f=await fixture(),other=generateMlKem768KeyPair();
 const bad=await f.seal({...f.identity,pqc:{...f.identity.pqc,mlKemPrivateKeyPkcs8:other.privateKeyPkcs8}});
 await assert.rejects(verifyOfflinePqRecovery(bad,password,f.pins));
});
