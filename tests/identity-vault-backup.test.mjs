import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import ts from "typescript";
// Unit-test the actual Vault implementation while replacing only the unrelated
// framework alias with the existing legacy fingerprint calculation.
const text = await readFile(new URL("../lib/quantic/vault.ts",import.meta.url),"utf8");
const source = text.replace('import { fingerprintPublicKey } from "@/lib/quantic/crypto";', `
async function fingerprintPublicKey(key) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode("P-256:"+key.x+":"+key.y));
  return Array.from(new Uint8Array(digest),b=>b.toString(16).padStart(2,"0")).join("").slice(0,10);
}`);
const js = ts.transpileModule(source,{compilerOptions:{module:ts.ModuleKind.ESNext,target:ts.ScriptTarget.ES2022}}).outputText;
const {exportIdentityVault,importIdentityVault} = await import("data:text/javascript;base64,"+Buffer.from(js).toString("base64"));
async function identity(){
  const e=await crypto.subtle.generateKey({name:"ECDH",namedCurve:"P-256"},true,["deriveKey"]);
  const s=await crypto.subtle.generateKey({name:"ECDSA",namedCurve:"P-256"},true,["sign","verify"]);
  return {handle:"lab-user",publicKey:await crypto.subtle.exportKey("jwk",e.publicKey),privateKey:await crypto.subtle.exportKey("jwk",e.privateKey),signingPublicKey:await crypto.subtle.exportKey("jwk",s.publicKey),signingPrivateKey:await crypto.subtle.exportKey("jwk",s.privateKey),createdAt:new Date().toISOString()};
}
async function legacy(i,password){
  const salt=crypto.getRandomValues(new Uint8Array(16)),iv=crypto.getRandomValues(new Uint8Array(12));
  const base=await crypto.subtle.importKey("raw",new TextEncoder().encode(password),"PBKDF2",false,["deriveKey"]);
  const key=await crypto.subtle.deriveKey({name:"PBKDF2",hash:"SHA-256",salt,iterations:250000},base,{name:"AES-GCM",length:256},false,["encrypt"]);
  const c=await crypto.subtle.encrypt({name:"AES-GCM",iv,additionalData:new TextEncoder().encode("quantic-identity-vault:v1")},key,new TextEncoder().encode(JSON.stringify(i)));
  return JSON.stringify({format:"quantic-identity-vault",version:1,createdAt:i.createdAt,kdf:{name:"PBKDF2",hash:"SHA-256",salt:Buffer.from(salt).toString("base64"),iterations:250000},cipher:{name:"AES-GCM",iv:Buffer.from(iv).toString("base64")},ciphertext:Buffer.from(c).toString("base64")});
}
const password="synthetic-test-passphrase-2026";
test("strong new exports and legacy Quantic JWKs remain readable",async()=>{
 const i=await identity(),backup=await exportIdentityVault(i,password);
 assert.equal(JSON.parse(backup).kdf.iterations,600000);
 assert.equal((await importIdentityVault(backup,password)).privateKey.d,i.privateKey.d);
 const old=await legacy(i,"oldpass123");
 assert.equal((await importIdentityVault(old,"oldpass123")).signingPrivateKey.d,i.signingPrivateKey.d);
 await assert.rejects(exportIdentityVault(i,"oldpass123"));
});
test("bad password, mismatched key pairs and malformed envelope rejected",async()=>{
 const i=await identity(),other=await identity(),backup=await exportIdentityVault(i,password);
 await assert.rejects(importIdentityVault(backup,"different-password"));
 await assert.rejects(exportIdentityVault({...i,privateKey:other.privateKey},password));
 await assert.rejects(importIdentityVault(await legacy({...i,signingPrivateKey:other.signingPrivateKey},password),password));
 for(const edit of [v=>v.kdf.iterations=250000.5,v=>v.kdf.salt="AA==",v=>v.cipher.iv="AA==",v=>v.ciphertext="!!!"]){
   const v=JSON.parse(backup);edit(v);await assert.rejects(importIdentityVault(JSON.stringify(v),password));
 }
 await assert.rejects(importIdentityVault("x".repeat(1000001),password));
});
