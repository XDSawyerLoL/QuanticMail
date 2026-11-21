import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync,sign} from 'node:crypto';
import {verifyMigrationArchiveOffline,openVerifiedMigrationHistory} from '../lib/quantic/migration-proof-node.mjs';
import {prepareMigrationArchive,sealMigrationArchive} from '../lib/quantic/migration-archive.ts';
import {canonicalManifestText} from '../lib/quantic/manifest-core.mjs';
import {canonicalPreKeyText} from '../lib/quantic/prekey-core.mjs';
import {deviceIdForPublicKeyNode,fingerprintPublicKeyNode} from '../lib/quantic/manifest-node.mjs';
import {generateMlKem768KeyPair,generateMlDsa65KeyPair} from '../lib/quantic/pqc-runtime-node.ts';
const pass='synthetic archive recovery only';
const pair=()=>generateKeyPairSync('ec',{namedCurve:'prime256v1'});
const pub=k=>k.publicKey.export({format:'jwk'}),priv=k=>k.privateKey.export({format:'jwk'});
const date='2026-11-21T00:00:00.000Z';
function fixture(){
 const root=pair(),enc=pair(),device=pair(),prekey=pair(),kem=generateMlKem768KeyPair(),dsa=generateMlDsa65KeyPair();
 const fingerprint=fingerprintPublicKeyNode(pub(root),32),canonicalAddress='alice~'+fingerprint+'@quantic',deviceId=deviceIdForPublicKeyNode(pub(enc),32);
 const payload={version:1,sequence:1,canonicalAddress,handle:'alice',fingerprint,identityPublicKey:pub(enc),identitySigningPublicKey:pub(root),devices:[{deviceId,label:'Offline fixture',publicKey:pub(enc),deviceSigningPublicKey:pub(device),kind:'root',issuedAt:date}],revocations:[],issuedAt:date};
 const manifest={format:'quantic-identity-manifest',version:1,payload,signature:sign('sha256',Buffer.from(canonicalManifestText(payload)),{key:root.privateKey,dsaEncoding:'ieee-p1363'}).toString('base64')};
 const identity={role:'root',handle:'alice',canonicalAddress,fingerprint,deviceId,publicKey:pub(enc),privateKey:priv(enc),signingPublicKey:pub(root),signingPrivateKey:priv(root),deviceSigningPublicKey:pub(device),deviceSigningPrivateKey:priv(device),manifest,pqc:{version:1,mlKemPublicKeySpki:kem.publicKeySpki,mlKemPrivateKeyPkcs8:kem.privateKeyPkcs8,mlDsaPublicKeySpki:dsa.publicKeySpki,mlDsaPrivateKeyPkcs8:dsa.privateKeyPkcs8},authToken:'never-exported'};
 const historical={version:1,canonicalAddress,deviceId,preKeyId:'c'.repeat(32),state:'claimed',publicKey:pub(prekey),privateKey:priv(prekey),createdAt:date,expiresAt:'2026-11-22T00:00:00.000Z'};
 historical.signature=sign('sha256',Buffer.from(canonicalPreKeyText(historical)),{key:device.privateKey,dsaEncoding:'ieee-p1363'}).toString('base64');
 const archive=prepareMigrationArchive({identity,pending:null,prekeys:[historical],messages:[],contacts:[],outbox:[]});
 return {archive,scope:{expectedAddress:canonicalAddress,trustedRootPin:createHash('sha256').update(root.publicKey.export({format:'der',type:'spki'})).digest('hex')}};
}
test('offline migration verifies original root, manifest and real classical plus PQ key possession without cutover',async()=>{
 const {archive,scope}=fixture();
 const result=await verifyMigrationArchiveOffline(await sealMigrationArchive(archive,pass),pass,scope);
 assert.equal(result.historicalRootPinVerified,true);assert.equal(result.rootPrivateKeyVerified,true);assert.equal(result.deviceKeyPossessionVerified,true);assert.equal(result.postQuantumKeyPairsVerified,true);assert.equal(result.prekeyPairsVerified,1);assert.equal(result.historicalPrekeySignaturesVerified,1);assert.equal(result.syntheticLegacyEnvelopeRecoveryVerified,true);
 assert.equal(result.liveRestoreAuthorized,false);assert.equal(result.legacyDeletionAuthorized,false);
 assert.ok(!JSON.stringify(result).includes(archive.identity.privateKey.d));
});
test('valid archive encryption cannot authorize mismatched root, substituted device or PQ keys',async()=>{
 const {archive,scope}=fixture();
 const text=await sealMigrationArchive(archive,pass);
 await assert.rejects(verifyMigrationArchiveOffline(text,pass,{...scope,trustedRootPin:'f'.repeat(64)}));
 const key=pair();const bad=structuredClone(archive);bad.identity.privateKey=priv(key);
 await assert.rejects(verifyMigrationArchiveOffline(await sealMigrationArchive(bad,pass),pass,scope));
 const badPQ=structuredClone(archive);badPQ.identity.pqc.mlKemPrivateKeyPkcs8=generateMlKem768KeyPair().privateKeyPkcs8;
 await assert.rejects(verifyMigrationArchiveOffline(await sealMigrationArchive(badPQ,pass),pass,scope));
 const stale=structuredClone(archive);stale.identity.manifest.payload.sequence=2;
 await assert.rejects(verifyMigrationArchiveOffline(await sealMigrationArchive(stale,pass),pass,scope));
});

test('archive authentication alone cannot substitute a historical signed prekey',async()=>{
 const {archive,scope}=fixture();
 const changed=structuredClone(archive);changed.prekeys[0].expiresAt='2026-12-01T00:00:00.000Z';
 await assert.rejects(verifyMigrationArchiveOffline(await sealMigrationArchive(changed,pass),pass,scope));
 const other=pair();const replaced=structuredClone(archive);replaced.prekeys[0].publicKey=pub(other);replaced.prekeys[0].privateKey=priv(other);
 await assert.rejects(verifyMigrationArchiveOffline(await sealMigrationArchive(replaced,pass),pass,scope));
});

test('verified history reopens archived messages only without making a live account or exposing keys',async()=>{
 const {archive,scope}=fixture();
 archive.messages=[{id:'m1',direction:'in',from:'bob@quantic',to:scope.expectedAddress,createdAt:date,subject:'past message',body:'stored body\u001b[31m'}];
 const text=await sealMigrationArchive(archive,pass),history=await openVerifiedMigrationHistory(text,pass,scope);
 assert.equal(history.records.length,1);assert.equal(history.records[0].subject,'past message');assert.equal(history.records[0].body,'stored body<U+001B>[31m');
 assert.equal(history.liveRestoreAuthorized,false);assert.equal(history.legacyDeletionAuthorized,false);
 assert.ok(!JSON.stringify(history).includes(archive.identity.privateKey.d));assert.equal(history.records[0].id,undefined);
 await assert.rejects(openVerifiedMigrationHistory(text,pass,{...scope,trustedRootPin:'f'.repeat(64)}));
 archive.messages.push(archive.messages[0]);await assert.rejects(openVerifiedMigrationHistory(await sealMigrationArchive(archive,pass),pass,scope));
});
