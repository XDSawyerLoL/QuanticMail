import test from "node:test";
import assert from "node:assert/strict";
import {summarizeMigration} from "../lib/quantic/migration-inventory.ts";
const c={pendingDevice:false,prekeys:0,messages:0,outbox:0,contacts:0};
test("inventory returns counts and flags without secret material or identifiers",()=>{
 const secret="PRIVATE_TEST_MATERIAL", identity={role:"root",canonicalAddress:"alice~"+"a".repeat(32)+"@quantic",privateKey:{d:secret},signingPrivateKey:{d:secret},deviceSigningPrivateKey:{d:secret},authToken:secret,pqc:{mlKemPrivateKeyPkcs8:secret,mlDsaPrivateKeyPkcs8:secret},manifest:{}};
 const before=structuredClone(identity);
 const result=summarizeMigration(identity,{...c,prekeys:7,messages:8,outbox:2,contacts:3,pendingDevice:true});
 assert.deepEqual(identity,before);
 assert.equal(result.rootSigningSecret,true);assert.equal(result.postQuantumSecrets,2);
 assert.equal(result.prekeys,7);assert.equal(result.canRemoveLegacyKeys,false);
 assert.ok(result.blockers.includes("local-mail-data-not-in-identity-backup"));
 assert.ok(result.blockers.includes("pending-pairing-must-be-resolved"));
 assert.ok(!JSON.stringify(result).includes(secret));assert.ok(!JSON.stringify(result).includes(identity.canonicalAddress));
});
test("empty and historical identities never permit deletion",()=>{
 for(const input of [null,{role:"secondary",canonicalAddress:"alice~"+"a".repeat(10)+"@quantic"},{canRemoveLegacyKeys:true}]) {
  const result=summarizeMigration(input,c);assert.equal(result.canRemoveLegacyKeys,false);
  assert.ok(result.blockers.includes("canonical-address-needs-review"));
 }
});
test("malformed counters are not silently converted to clean inventory",()=>{
 for(const prekeys of [-1,NaN,Infinity,1.5])assert.throws(()=>summarizeMigration({}, {...c,prekeys}));
});
