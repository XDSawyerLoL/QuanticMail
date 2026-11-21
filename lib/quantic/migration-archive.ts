// Offline recovery archive; not an authorization, registration or live restore format.
import type {LocalIdentity,LocalPreKey,LocalMessage,LocalContact,LocalOutboxItem,LocalPendingDevice} from "./local-db";
export const ARCHIVE_MAX_BYTES=16*1024*1024;
export const ARCHIVE_MAX_ROWS=10000;
const FORMAT="quantic-migration-archive";
const ITERATIONS=600000;
const aad=new TextEncoder().encode(FORMAT+":v1:PBKDF2-SHA256-600000:AES-256-GCM");
type IdentityCopy=Omit<LocalIdentity,"authToken">;
type PendingCopy=Omit<LocalPendingDevice,"authToken">;
export type MigrationSnapshot={identity:LocalIdentity;pending:LocalPendingDevice|null;prekeys:LocalPreKey[];messages:LocalMessage[];contacts:LocalContact[];outbox:LocalOutboxItem[]};
export type MigrationArchive={identity:IdentityCopy;pending:PendingCopy|null;prekeys:LocalPreKey[];messages:LocalMessage[];contacts:LocalContact[];outbox:LocalOutboxItem[]};
function check(ok:unknown,message="Archive de migration invalide."):asserts ok{if(!ok)throw Error(message);}
function obj(v:unknown):v is Record<string,unknown>{return !!v&&typeof v==="object"&&!Array.isArray(v);}
function b64(bytes:Uint8Array){let s="";for(let i=0;i<bytes.length;i+=8192)s+=String.fromCharCode(...bytes.subarray(i,i+8192));return btoa(s);}
function decode(value:unknown,min:number,max:number){
 check(typeof value==="string"&&value.length<=Math.ceil(max/3)*4);
 const s=atob(value);check(s.length>=min&&s.length<=max);
 const b=Uint8Array.from(s,c=>c.charCodeAt(0));check(b64(b)===value);return b;
}
function bytes(v:Uint8Array){return new Uint8Array(v).buffer;}
function passwordOK(p:string){check(typeof p==="string"&&p.length>=14&&p.length<=1024,"Phrase secrète de 14 à 1024 caractères requise.");}
async function key(p:string,salt:Uint8Array){
 const k=await crypto.subtle.importKey("raw",new TextEncoder().encode(p),"PBKDF2",false,["deriveKey"]);
 return crypto.subtle.deriveKey({name:"PBKDF2",hash:"SHA-256",salt:bytes(salt),iterations:ITERATIONS},k,{name:"AES-GCM",length:256},false,["encrypt","decrypt"]);
}
function address(v:unknown){return typeof v==="string"&&/^[a-z0-9][a-z0-9._-]{2,31}~(?:[0-9a-f]{10}|[0-9a-f]{32})@quantic$/.test(v);}
function validate(v:unknown):asserts v is MigrationArchive{
 check(obj(v)&&obj(v.identity)&&address(v.identity.canonicalAddress)&&obj(v.identity.privateKey)&&obj(v.identity.publicKey));
 check(v.pending===null||obj(v.pending));
 for(const name of ["prekeys","messages","contacts","outbox"]){
   const rows=v[name];check(Array.isArray(rows)&&rows.length<=ARCHIVE_MAX_ROWS&&rows.every(obj));
 }
 // Never restore bearer credentials from this format, even if a modified generator supplies one.
 check(!("authToken" in v.identity)&&(!v.pending||!("authToken" in v.pending)));
}
export function prepareMigrationArchive(s:MigrationSnapshot):MigrationArchive{
 // Preserve captured records exactly except explicitly excluded live bearer secrets.
 const identity={...s.identity};delete (identity as Partial<LocalIdentity>).authToken;
 const pending=s.pending?{...s.pending}:null;
 if(pending)delete (pending as Partial<LocalPendingDevice>).authToken;
 const v={identity,pending,prekeys:s.prekeys,messages:s.messages,contacts:s.contacts,outbox:s.outbox};
 validate(v);return v;
}
export async function sealMigrationArchive(v:MigrationArchive,p:string){
 passwordOK(p);validate(v);
 const raw=new TextEncoder().encode(JSON.stringify(v));check(raw.length<=ARCHIVE_MAX_BYTES,"Archive trop volumineuse : aucune donnée supprimée.");
 try{
  const salt=crypto.getRandomValues(new Uint8Array(16)),iv=crypto.getRandomValues(new Uint8Array(12));
  const k=await key(p,salt);
  const c=await crypto.subtle.encrypt({name:"AES-GCM",iv,additionalData:aad},k,raw);
  return JSON.stringify({format:FORMAT,version:1,iterations:ITERATIONS,salt:b64(salt),iv:b64(iv),ciphertext:b64(new Uint8Array(c))});
 }finally{raw.fill(0);}
}
export async function openMigrationArchive(text:string,p:string,expectedAddress:string):Promise<MigrationArchive>{
 passwordOK(p);check(address(expectedAddress),"Adresse canonique d’origine obligatoire.");
 check(typeof text==="string"&&text.length<=Math.ceil((ARCHIVE_MAX_BYTES+16)/3)*4+512);
 const e:unknown=JSON.parse(text);check(obj(e)&&e.format===FORMAT&&e.version===1&&e.iterations===ITERATIONS);
 const salt=decode(e.salt,16,16),iv=decode(e.iv,12,12),ciphertext=decode(e.ciphertext,16,ARCHIVE_MAX_BYTES+16);
 const k=await key(p,salt);
 let raw:Uint8Array|undefined;
 try{
  raw=new Uint8Array(await crypto.subtle.decrypt({name:"AES-GCM",iv:bytes(iv),additionalData:aad},k,bytes(ciphertext)));
  const v:unknown=JSON.parse(new TextDecoder("utf-8",{fatal:true}).decode(raw));validate(v);
  check(v.identity.canonicalAddress===expectedAddress,"Archive d’une autre identité.");
  return v;
 }finally{raw?.fill(0);}
}
export function migrationArchiveSummary(v:MigrationArchive){
 validate(v);
 return {prekeys:v.prekeys.length,messages:v.messages.length,contacts:v.contacts.length,outbox:v.outbox.length,pending:!!v.pending,pqMaterial:!!v.identity.pqc,liveRestoreAuthorized:false as const};
}
