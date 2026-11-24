import test from "node:test";
import assert from "node:assert/strict";
import {generateKeyPairSync,createHash} from "node:crypto";
import {prepareMigrationArchive,sealMigrationArchive,openMigrationArchive,migrationArchiveSummary,reconcileMigrationSnapshot,migrationRootPin} from "../lib/quantic/migration-archive.ts";
import {encryptForRecipientCore,decryptEnvelopeCore} from "../lib/quantic/envelope-crypto.mjs";
const pass="synthetic long archive secret only";
const pair=()=>generateKeyPairSync("ec",{namedCurve:"prime256v1"});
const address="alice~"+"a".repeat(32)+"@quantic";
test("encrypted migration snapshot preserves historical decryptability without copying bearer tokens",async()=>{
 const p=pair(),q=pair();
 const pub=k=>k.publicKey.export({format:"jwk"}),priv=k=>k.privateKey.export({format:"jwk"});
 const snap={identity:{canonicalAddress:address,privateKey:priv(p),publicKey:pub(p),authToken:"LIVE_TOKEN",pqc:{mlKemPrivateKeyPkcs8:"synthetic",mlDsaPrivateKeyPkcs8:"synthetic"}},pending:{authToken:"PENDING_TOKEN",privateKey:priv(q)},prekeys:[{privateKey:priv(q),publicKey:pub(q),state:"claimed"}],messages:[{id:"m",body:"historic plaintext"}],contacts:[{handle:"bob"}],outbox:[{id:"out"}]};
 const archive=prepareMigrationArchive(snap);
 const text=await sealMigrationArchive(archive,pass);
 assert.ok(!text.includes("historic plaintext"));assert.ok(!text.includes("LIVE_TOKEN"));
 const r=await openMigrationArchive(text,pass,address);
 assert.deepEqual(r,archive);assert.equal(snap.identity.authToken,"LIVE_TOKEN");assert.ok(!JSON.stringify(r).includes("PENDING_TOKEN"));
 assert.deepEqual(await decryptEnvelopeCore(r.identity.privateKey,await encryptForRecipientCore(pub(p),{body:"old mail"})),{body:"old mail"});
 assert.deepEqual(await decryptEnvelopeCore(r.prekeys[0].privateKey,await encryptForRecipientCore(pub(q),{body:"old prekey mail"})),{body:"old prekey mail"});
 assert.equal(r.prekeys[0].state,"claimed");
 assert.equal(migrationArchiveSummary(r).liveRestoreAuthorized,false);
 await assert.rejects(openMigrationArchive(text,"wrong password long enough",address));
 await assert.rejects(openMigrationArchive(text,pass,"bob~"+"b".repeat(32)+"@quantic"));
 const bad=JSON.parse(text),c=Buffer.from(bad.ciphertext,"base64");c[0]^=1;bad.ciphertext=c.toString("base64");
 await assert.rejects(openMigrationArchive(JSON.stringify(bad),pass,address));
 bad.iterations=1;await assert.rejects(openMigrationArchive(JSON.stringify(bad),pass,address));
});
test("archive rejects incomplete identity and credentials inserted into archive",async()=>{
 assert.throws(()=>prepareMigrationArchive({identity:{},pending:null,prekeys:[],messages:[],contacts:[],outbox:[]}));
 await assert.rejects(sealMigrationArchive({identity:{canonicalAddress:address,privateKey:{},publicKey:{},authToken:"x"},pending:null,prekeys:[],messages:[],contacts:[],outbox:[]},pass));
});

test("recovered ML-KEM and ML-DSA material performs real historical operations",async()=>{
 const pq=await import("../lib/quantic/pqc-runtime-node.ts");
 const kem=pq.generateMlKem768KeyPair(),dsa=pq.generateMlDsa65KeyPair(),p=pair();
 const secret=pq.mlKemEncapsulate(kem.publicKeySpki);
 const identity={canonicalAddress:address,publicKey:p.publicKey.export({format:"jwk"}),privateKey:p.privateKey.export({format:"jwk"}),authToken:"exclude",pqc:{version:1,mlKemPublicKeySpki:kem.publicKeySpki,mlKemPrivateKeyPkcs8:kem.privateKeyPkcs8,mlDsaPublicKeySpki:dsa.publicKeySpki,mlDsaPrivateKeyPkcs8:dsa.privateKeyPkcs8,createdAt:new Date().toISOString()}};
 const a=prepareMigrationArchive({identity,pending:null,prekeys:[],messages:[],contacts:[],outbox:[]});
 const restored=await openMigrationArchive(await sealMigrationArchive(a,pass),pass,address);
 const m=restored.identity.pqc;
 assert.deepEqual(pq.mlKemDecapsulate(m.mlKemPrivateKeyPkcs8,secret.ciphertext),secret.sharedSecret);
 const data=Buffer.from("synthetic historical recovery challenge");
 const signature=pq.mlDsaSign(m.mlDsaPrivateKeyPkcs8,data);
 assert.equal(pq.mlDsaVerify(dsa.publicKeySpki,data,signature),true);
 assert.equal(pq.mlDsaVerify(dsa.publicKeySpki,Buffer.from("changed"),signature),false);
});

test("read-only reconciliation detects missing changed and extra records and ignores bearer rotation",()=>{
 const p=pair(),source={identity:{canonicalAddress:address,privateKey:p.privateKey.export({format:"jwk"}),publicKey:p.publicKey.export({format:"jwk"}),authToken:"original"},pending:null,prekeys:[{preKeyId:"p",state:"claimed"}],messages:[{id:"a",body:"alpha"},{id:"b",body:"beta"}],contacts:[{handle:"bob"}],outbox:[{id:"o"}]};
 const saved=prepareMigrationArchive(source);
 const frozen=JSON.stringify(source);
 const changed=structuredClone(source);changed.identity.authToken="rotated";changed.messages.reverse();
 assert.equal(reconcileMigrationSnapshot(saved,changed).snapshotMatches,true);
 changed.messages=[{id:"a",body:"modified"},{id:"c",body:"new"}];changed.prekeys[0].state="unused";
 const report=reconcileMigrationSnapshot(saved,changed);
 assert.equal(report.snapshotMatches,false);
 assert.deepEqual(report.rows.find(x=>x.category==="messages"),{category:"messages",missing:1,changed:1,extra:1,sourceCount:2,archiveCount:2});
 assert.equal(report.rows.find(x=>x.category==="prekeys").changed,1);
 assert.equal(report.liveRestoreAuthorized,false);assert.equal(report.legacyDeletionAuthorized,false);
 assert.equal(JSON.stringify(source),frozen);assert.ok(!JSON.stringify(report).includes("modified"));
 const dup=structuredClone(saved);dup.messages.push(dup.messages[0]);assert.throws(()=>reconcileMigrationSnapshot(dup,source));
 const wrong=structuredClone(source);wrong.identity.canonicalAddress="bob~"+"b".repeat(32)+"@quantic";assert.throws(()=>reconcileMigrationSnapshot(saved,wrong));
});

test("source public reference interoperates with the Node offline verifier",async()=>{
 const p=pair(),pub=p.publicKey.export({format:"jwk"});
 assert.equal(await migrationRootPin(pub),createHash("sha256").update(p.publicKey.export({format:"der",type:"spki"})).digest("hex"));
 assert.notEqual(await migrationRootPin(pub),await migrationRootPin(pair().publicKey.export({format:"jwk"})));
 await assert.rejects(migrationRootPin(p.privateKey.export({format:"jwk"})));
 await assert.rejects(migrationRootPin({kty:"EC",crv:"P-256",x:"bad",y:"bad"}));
});
