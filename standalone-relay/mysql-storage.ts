import {
  createCipheriv,
  createDecipheriv,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  randomBytes,
  scryptSync,
} from "node:crypto";

import type { RelayPersistentState } from "../lib/quantic/relay-state.ts";
import { relayIdForPublicKey, type RelayIdentity } from "./identity.ts";
import type { RelayStateStore } from "./storage.ts";

export type MySqlQueryClient={
  execute(sql:string,params?:unknown[]):Promise<[unknown[],{affectedRows?:number}]>;
};

export type MySqlPersistenceOptions={identitySecret?:string};

type EncryptedRelayIdentity={
  format:"quantic-relay-identity-encrypted";
  version:1;
  kdf:"scrypt";
  cipher:"aes-256-gcm";
  salt:string;
  iv:string;
  ciphertext:string;
  tag:string;
};

const STATE_KEY="relay-state";
const IDENTITY_KEY="relay-identity";
const IDENTITY_AAD=Buffer.from("quantic-relay-identity-v1","utf8");
const CREATE_TABLE_SQL=`
  CREATE TABLE IF NOT EXISTS quantic_relay_kv (
    \`key\` VARCHAR(64) PRIMARY KEY,
    \`value\` LONGTEXT NOT NULL,
    revision BIGINT UNSIGNED NOT NULL DEFAULT 0,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
`;

export class MySqlRelayStateConflictError extends Error{
  constructor(){
    super("Conflit de révision MySQL Quantic Relay : un autre processus a écrit un état plus récent.");
    this.name="MySqlRelayStateConflictError";
  }
}

function rows(value:unknown):Array<Record<string,unknown>>{
  return Array.isArray(value)?value as Array<Record<string,unknown>>:[];
}

function parseValue(value:unknown){
  if(value===undefined||value===null)return null;
  if(typeof value==="string")return JSON.parse(value) as unknown;
  if(Buffer.isBuffer(value))return JSON.parse(value.toString("utf8")) as unknown;
  return value;
}

function parseRevision(value:unknown){
  if(value===undefined||value===null)return null;
  const n=Number(value);
  if(!Number.isSafeInteger(n)||n<0)throw new Error("Révision MySQL Quantic Relay invalide.");
  return n;
}

function createRelayIdentity():RelayIdentity{
  const pair=generateKeyPairSync("ec",{namedCurve:"prime256v1"});
  const publicKeyJwk=pair.publicKey.export({format:"jwk"}) as JsonWebKey;
  const privateKeyPem=pair.privateKey.export({type:"pkcs8",format:"pem"}).toString();
  return {relayId:relayIdForPublicKey(publicKeyJwk),publicKeyJwk,privateKeyPem};
}

function assertRelayIdentity(value:unknown):RelayIdentity{
  const identity=value as Partial<RelayIdentity>|null;
  if(!identity||typeof identity.relayId!=="string"||!/^[0-9a-f]{64}$/.test(identity.relayId)||!identity.publicKeyJwk||typeof identity.privateKeyPem!=="string"){
    throw new Error("Identité MySQL Quantic Relay invalide.");
  }
  const expected=relayIdForPublicKey(identity.publicKeyJwk);
  if(expected!==identity.relayId)throw new Error("Relay ID MySQL incohérent avec sa clé publique.");
  const publicFromPrivate=createPublicKey(createPrivateKey(identity.privateKeyPem)).export({format:"jwk"}) as JsonWebKey;
  if(
    publicFromPrivate.kty!==identity.publicKeyJwk.kty||
    publicFromPrivate.crv!==identity.publicKeyJwk.crv||
    publicFromPrivate.x!==identity.publicKeyJwk.x||
    publicFromPrivate.y!==identity.publicKeyJwk.y
  )throw new Error("La clé privée MySQL ne correspond pas au Relay ID.");
  return identity as RelayIdentity;
}

function requireIdentitySecret(value?:string){
  if(value===undefined)return null;
  if(value.length<32)throw new Error("QUANTIC_RELAY_IDENTITY_SECRET doit contenir au moins 32 caractères.");
  return value;
}

function isEncryptedIdentity(value:unknown):value is EncryptedRelayIdentity{
  const record=value as Partial<EncryptedRelayIdentity>|null;
  return Boolean(record&&record.format==="quantic-relay-identity-encrypted"&&record.version===1&&record.kdf==="scrypt"&&record.cipher==="aes-256-gcm"&&typeof record.salt==="string"&&typeof record.iv==="string"&&typeof record.ciphertext==="string"&&typeof record.tag==="string");
}

function deriveIdentityKey(secret:string,salt:Buffer){
  return scryptSync(secret,salt,32,{N:16_384,r:8,p:1,maxmem:64*1024*1024});
}

function encryptRelayIdentity(identity:RelayIdentity,secret:string):EncryptedRelayIdentity{
  const salt=randomBytes(16);
  const iv=randomBytes(12);
  const cipher=createCipheriv("aes-256-gcm",deriveIdentityKey(secret,salt),iv);
  cipher.setAAD(IDENTITY_AAD);
  const ciphertext=Buffer.concat([cipher.update(Buffer.from(JSON.stringify(identity),"utf8")),cipher.final()]);
  const tag=cipher.getAuthTag();
  return {
    format:"quantic-relay-identity-encrypted",version:1,kdf:"scrypt",cipher:"aes-256-gcm",
    salt:salt.toString("base64url"),iv:iv.toString("base64url"),ciphertext:ciphertext.toString("base64url"),tag:tag.toString("base64url"),
  };
}

function decryptRelayIdentity(record:EncryptedRelayIdentity,secret:string){
  try{
    const salt=Buffer.from(record.salt,"base64url");
    const iv=Buffer.from(record.iv,"base64url");
    const tag=Buffer.from(record.tag,"base64url");
    const ciphertext=Buffer.from(record.ciphertext,"base64url");
    if(salt.length!==16||iv.length!==12||tag.length!==16||ciphertext.length<16)throw new Error("format");
    const decipher=createDecipheriv("aes-256-gcm",deriveIdentityKey(secret,salt),iv);
    decipher.setAAD(IDENTITY_AAD);
    decipher.setAuthTag(tag);
    const plaintext=Buffer.concat([decipher.update(ciphertext),decipher.final()]).toString("utf8");
    return assertRelayIdentity(JSON.parse(plaintext));
  }catch{
    throw new Error("Secret d’identité Quantic Relay incorrect ou identité chiffrée impossible à déchiffrer/authentifier.");
  }
}

export function createMySqlRelayPersistence(client:MySqlQueryClient,options:MySqlPersistenceOptions={}){
  let initialized=false;
  let stateRevision:number|null=null;
  const identitySecret=requireIdentitySecret(options.identitySecret);

  async function initialize(){
    if(initialized)return;
    await client.execute(CREATE_TABLE_SQL);
    initialized=true;
  }

  async function readValue(key:string){
    await initialize();
    const [result]=await client.execute("SELECT value FROM quantic_relay_kv WHERE `key` = ?",[key]);
    return parseValue(rows(result)[0]?.value);
  }

  async function saveValue(key:string,value:unknown){
    await initialize();
    const serialized=JSON.stringify(value);
    await client.execute(
      "INSERT INTO quantic_relay_kv (`key`, value, revision) VALUES (?, ?, 0) ON DUPLICATE KEY UPDATE value = VALUES(value), updated_at = CURRENT_TIMESTAMP",
      [key,serialized],
    );
  }

  async function loadState(){
    await initialize();
    const [result]=await client.execute("SELECT value, revision FROM quantic_relay_kv WHERE `key` = ?",[STATE_KEY]);
    const row=rows(result)[0];
    const value=parseValue(row?.value);
    stateRevision=value===null?null:parseRevision(row?.revision);
    return value as RelayPersistentState|null;
  }

  async function saveState(state:RelayPersistentState){
    await initialize();
    const serialized=JSON.stringify(state);
    if(stateRevision===null){
      const [,info]=await client.execute(
        "INSERT IGNORE INTO quantic_relay_kv (`key`, value, revision) VALUES (?, ?, ?)",
        [STATE_KEY,serialized,1],
      );
      if(Number(info.affectedRows??0)!==1)throw new MySqlRelayStateConflictError();
      stateRevision=1;
      return;
    }

    const [,info]=await client.execute(
      "UPDATE quantic_relay_kv SET value = ?, revision = revision + 1, updated_at = CURRENT_TIMESTAMP WHERE `key` = ? AND revision = ?",
      [serialized,STATE_KEY,stateRevision],
    );
    if(Number(info.affectedRows??0)!==1)throw new MySqlRelayStateConflictError();
    stateRevision+=1;
  }

  const stateStore:RelayStateStore={load:loadState,save:saveState};

  function decodeStoredIdentity(value:unknown){
    if(isEncryptedIdentity(value)){
      if(!identitySecret)throw new Error("QUANTIC_RELAY_IDENTITY_SECRET est requis pour cette identité MySQL chiffrée.");
      return decryptRelayIdentity(value,identitySecret);
    }
    return assertRelayIdentity(value);
  }

  function encodedIdentity(identity:RelayIdentity){
    return identitySecret?encryptRelayIdentity(identity,identitySecret):identity;
  }

  async function loadOrCreateIdentity(){
    const existing=await readValue(IDENTITY_KEY);
    if(existing){
      const identity=decodeStoredIdentity(existing);
      if(identitySecret&&!isEncryptedIdentity(existing)){
        await saveValue(IDENTITY_KEY,encryptRelayIdentity(identity,identitySecret));
      }
      return identity;
    }

    const generated=createRelayIdentity();
    const encoded=encodedIdentity(generated);
    const [,info]=await client.execute(
      "INSERT IGNORE INTO quantic_relay_kv (`key`, value, revision) VALUES (?, ?, ?)",
      [IDENTITY_KEY,JSON.stringify(encoded),0],
    );
    if(Number(info.affectedRows??0)===1)return generated;

    const raced=await readValue(IDENTITY_KEY);
    if(!raced)throw new Error("Impossible de relire l’identité MySQL Quantic Relay.");
    return decodeStoredIdentity(raced);
  }

  return {initialize,stateStore,loadOrCreateIdentity};
}

export async function createMySqlRelayPersistenceFromConfig(
  config:{host:string;port?:number;user:string;password?:string;database:string},
  options:MySqlPersistenceOptions={}
){
  const mysql=await import("mysql2/promise");
  const pool=mysql.createPool({
    host:config.host,
    port:config.port??3306,
    user:config.user,
    password:config.password??"",
    database:config.database,
    connectionLimit:4,
    enableKeepAlive:true,
    charset:"utf8mb4",
  });
  const persistence=createMySqlRelayPersistence(pool as unknown as MySqlQueryClient,options);
  await persistence.initialize();
  return {...persistence,async close(){await pool.end();}};
}
