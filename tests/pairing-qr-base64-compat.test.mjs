import {test} from "node:test";
import assert from "node:assert/strict";
import {Buffer} from "node:buffer";
import {webcrypto} from "node:crypto";
import {randomPairingSecret,encryptPairingPackage,decryptPairingPackage} from "../lib/quantic/pairing-crypto.mjs";
import {createPairingStore,createInvite,pairingStatus} from "../lib/quantic/pairing-store.mjs";

test("Pairing QR works even when Buffer rejects base64url encoding",async()=>{
  if(!globalThis.crypto)globalThis.crypto=webcrypto;
  const originalFrom=Buffer.from,originalToString=Buffer.prototype.toString;
  Buffer.from=function(value,encoding,...args){
    if(encoding==="base64url")throw new TypeError("Unknown encoding: base64url");
    return Reflect.apply(originalFrom,Buffer,[value,encoding,...args]);
  };
  Buffer.prototype.toString=function(encoding,...args){
    if(encoding==="base64url")throw new TypeError("Unknown encoding: base64url");
    return Reflect.apply(originalToString,this,[encoding,...args]);
  };
  try{
    const secret=randomPairingSecret();
    assert.match(secret,/^[A-Za-z0-9_-]{43}$/);
    const store=createPairingStore();
    const invite=createInvite(store,{canonicalAddress:"personne@quantic.example",rootDeviceId:"root-device"},secret);
    assert.ok(pairingStatus(store,invite.inviteId,secret).expiresAt>Date.now());
    const data={deviceId:"device-2",messages:[{body:"Coucou !"}]};
    const payload=await encryptPairingPackage(secret,invite.inviteId,data);
    assert.match(payload.iv,/^[A-Za-z0-9_-]+$/);
    assert.deepEqual(await decryptPairingPackage(secret,invite.inviteId,payload),data);
    await assert.rejects(()=>decryptPairingPackage("x".repeat(43),invite.inviteId,payload));
    assert.throws(()=>pairingStatus(store,invite.inviteId,"A".repeat(43)));
  }finally{
    Buffer.from=originalFrom;
    Buffer.prototype.toString=originalToString;
  }
});
