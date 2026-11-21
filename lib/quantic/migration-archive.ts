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
 const identity=structuredClone(s.identity);delete (identity as Partial<LocalIdentity>).authToken;
 const pending=s.pending?structuredClone(s.pending):null;
 if(pending)delete (pending as Partial<LocalPendingDevice>).authToken;
 const v={identity,pending,prekeys:structuredClone(s.prekeys),messages:structuredClone(s.messages),contacts:structuredClone(s.contacts),outbox:structuredClone(s.outbox)};
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

// Compare a decrypted archive with a freshly captured source transaction.
// No disk/network writes; no disclosure of message contents, IDs or key material.
// Counts describe the sampled transaction, not a lock on subsequent writes.
function canonicalValue(v:unknown):string {
 if(v===null||typeof v==="boolean"||typeof v==="string"||typeof v==="number"){
  check(typeof v!=="number"||Number.isFinite(v));return JSON.stringify(v);
 }
 if(Array.isArray(v))return "["+v.map(canonicalValue).join(",")+"]";
 check(obj(v));
 const keys=Object.keys(v).filter(k=>v[k]!==undefined).sort();
 return "{"+keys.map(k=>JSON.stringify(k)+":"+canonicalValue(v[k])).join(",")+"}";
}
function rowMap(rows:unknown[],key:string){
 const map=new Map<string,string>();
 for(const row of rows){
  check(obj(row));const id=row[key];
  check(typeof id==="string"&&id.length>0&&id.length<=512&&!map.has(id),"Enregistrements dupliqués ou invalides.");
  map.set(id,canonicalValue(row));
 }
 return map;
}
export function reconcileMigrationSnapshot(archive:MigrationArchive,source:MigrationSnapshot){
 validate(archive);const current=prepareMigrationArchive(source);
 check(current.identity.canonicalAddress===archive.identity.canonicalAddress,"Identité différente.");
 const identityMatches=canonicalValue(current.identity)===canonicalValue(archive.identity);
 const pendingMatches=canonicalValue(current.pending)===canonicalValue(archive.pending);
 const categories=[["messages","id"],["contacts","handle"],["prekeys","preKeyId"],["outbox","id"]] as const;
 const rows=categories.map(([category,key])=>{
  const saved=rowMap(archive[category],key),live=rowMap(current[category],key);
  let missing=0,changed=0,extra=0;
  for(const [id,value] of live){
   if(!saved.has(id))missing++;
   else if(saved.get(id)!==value)changed++;
  }
  for(const id of saved.keys())if(!live.has(id))extra++;
  return {category,missing,changed,extra,sourceCount:live.size,archiveCount:saved.size};
 });
 return {identityMatches,pendingMatches,rows,snapshotMatches:identityMatches&&pendingMatches&&rows.every(r=>r.missing+r.changed+r.extra===0),liveRestoreAuthorized:false as const,legacyDeletionAuthorized:false as const};
}

/** Public reference for independently checking an exported archive.
 * Must be retained separately on the source device; never trust a reference
 * provided solely by an untrusted archive. This is not an enrollment grant.
 */
export async function migrationRootPin(publicKey:JsonWebKey):Promise<string>{
 check(publicKey?.kty==="EC"&&publicKey.crv==="P-256"&&typeof publicKey.x==="string"&&typeof publicKey.y==="string"&&!Object.hasOwn(publicKey,"d"),"Clé publique historique invalide.");
 const key=await crypto.subtle.importKey("jwk",{kty:"EC",crv:"P-256",x:publicKey.x,y:publicKey.y},{name:"ECDSA",namedCurve:"P-256"},true,["verify"]);
 const spki=await crypto.subtle.exportKey("spki",key);
 return Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256",spki)),b=>b.toString(16).padStart(2,"0")).join("");
}
