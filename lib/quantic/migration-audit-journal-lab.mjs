// Append-only synthetic audit journal for the encrypted Windows migration
// laboratory. The record is a NON-AUTHORIZING verification receipt, not a
// transaction commit, user-account migration, prekey activation or cutover.
// No key, token, historical ID or message content may enter the journal.
import {createCipheriv,createDecipheriv,createHash,randomBytes} from 'node:crypto';
const refuse=ok=>{if(!ok)throw Error('Immutable migration audit journal refused');};
const transaction=/^[a-f0-9]{32}$/;
const hex=/^[a-f0-9]{64}$/;
const domain='quantic-native-migration-audit-lab/v1';
const phases=['prepared','snapshot-verified','relay-observed','blocked'];
const fields=new Set(['sourceManifestSha256','candidateManifestSha256','relayIdSha256',
 'observedWindowSha256','historicalCollectionsMatch','observedRelayWindowStable',
 'observedRelayWindowNotAtCap','pendingIncomingVisible','pendingReceiptsVisible',
 'outboxPreserved','prekeysPreserved']);
const b64=x=>x.toString('base64url');
const decode=(s,min,max)=>{
 refuse(typeof s==='string'&&/^[A-Za-z0-9_-]+$/.test(s)&&s.length<=Math.ceil(max/3)*4);
 const b=Buffer.from(s,'base64url');refuse(b.length>=min&&b.length<=max&&b64(b)===s);return b;
};
function validateFacts(facts){
 refuse(facts&&Object.getPrototypeOf(facts)===Object.prototype&&Object.keys(facts).length>=1&&Object.keys(facts).length<=fields.size);
 for(const [key,value] of Object.entries(facts)){
  refuse(fields.has(key));
  if(key.endsWith('Sha256'))refuse(hex.test(value));
  else if(key.endsWith('Visible'))refuse(Number.isSafeInteger(value)&&value>=0&&value<=100);
  else refuse(typeof value==='boolean');
 }
 return facts;
}
function params(key,info){
 refuse(Buffer.isBuffer(key)&&key.length===32&&info&&hex.test(info.rootPin)
  &&transaction.test(info.transactionId));
}
function context(info,seq,previousHash,phase){
 refuse(Number.isSafeInteger(seq)&&seq>=0&&seq<=31&&hex.test(previousHash)
  &&phases.includes(phase)&&((seq===0&&phase==='prepared'&&previousHash==='0'.repeat(64))||seq>0));
 return Buffer.from(JSON.stringify([domain,info.rootPin,info.transactionId,seq,previousHash,phase]));
}
export function migrationAuditName(tx,seq){
 refuse(transaction.test(tx)&&Number.isSafeInteger(seq)&&seq>=0&&seq<=31);
 return 'a-'+tx+'-'+String(seq).padStart(3,'0')+'.enc';
}
export function sealMigrationAuditLabRecord(record,key,info){
 params(key,info);refuse(record&&typeof record==='object');
 const {sequence,phase,previousHash,facts}=record;
 const aad=context(info,sequence,previousHash,phase);
 validateFacts(facts);
 const plaintext=Buffer.from(JSON.stringify({phase,sequence,previousHash,facts}));
 refuse(plaintext.length<=4096);
 try{
  const iv=randomBytes(12),c=createCipheriv('aes-256-gcm',key,iv);c.setAAD(aad);
  const cipher=Buffer.concat([c.update(plaintext),c.final()]);
  const packet=Buffer.from(JSON.stringify({format:domain,version:1,transactionId:info.transactionId,
   sequence,phase,previousHash,iv:b64(iv),ciphertext:b64(cipher),tag:b64(c.getAuthTag())}));
  refuse(packet.length<=8192);return packet;
 }finally{plaintext.fill(0);}
}
export function openMigrationAuditLabRecord(packed,key,info,{sequence,previousHash,phase}){
 params(key,info);
 refuse(Buffer.isBuffer(packed)&&packed.length>=120&&packed.length<=8192);
 const parsed=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(packed));
 refuse(parsed&&Object.getPrototypeOf(parsed)===Object.prototype&&Object.keys(parsed).length===9
  &&parsed.format===domain&&parsed.version===1
  &&parsed.transactionId===info.transactionId&&parsed.sequence===sequence
  &&parsed.phase===phase&&parsed.previousHash===previousHash
  &&Buffer.from(JSON.stringify(parsed)).equals(packed));
 const aad=context(info,sequence,previousHash,phase);
 const iv=decode(parsed.iv,12,12),tag=decode(parsed.tag,16,16),cipher=decode(parsed.ciphertext,1,4096);
 let first,second,plain;
 try{
  const d=createDecipheriv('aes-256-gcm',key,iv);d.setAAD(aad);d.setAuthTag(tag);
  first=d.update(cipher);second=d.final();plain=Buffer.concat([first,second]);
  const item=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(plain));
  refuse(item&&Object.getPrototypeOf(item)===Object.prototype&&Object.keys(item).length===4
   &&item.phase===phase&&item.sequence===sequence&&item.previousHash===previousHash);
  validateFacts(item.facts);return item;
 }finally{first?.fill(0);second?.fill(0);plain?.fill(0);}
}
export function migrationAuditPacketHash(packet){
 refuse(Buffer.isBuffer(packet)&&packet.length<=8192&&packet.length>=120);
 return createHash('sha256').update(packet).digest('hex');
}
// Each step can only be written if its predecessor is independently read and
// authenticated; a process crash can only leave an absent or intact record.
// Idempotent replays must match the authenticated facts, not re-encrypt over.
export async function appendMigrationAuditLabRecord(storage,key,info,{sequence,phase,facts}){
 params(key,info);validateFacts(facts);
 refuse(storage&&typeof storage.probe==='function'&&typeof storage.read==='function'&&typeof storage.write==='function');
 const name=migrationAuditName(info.transactionId,sequence);
 let previousHash='0'.repeat(64);
 if(sequence>0){
  const previousName=migrationAuditName(info.transactionId,sequence-1);
  refuse(await storage.probe(previousName)==='present');
  const previous=await storage.read(previousName);
  // Previous phase is fixed for the first three stages. Later records are
  // deliberately blocked-only; no live commit phase exists.
  const prevPhase=sequence===1?'prepared':sequence===2?'snapshot-verified':sequence===3?'relay-observed':'blocked';
  const previousPreviousHash=sequence===1?'0'.repeat(64):await predecessorHash(storage,key,info,sequence-1);
  openMigrationAuditLabRecord(previous,key,info,{sequence:sequence-1,previousHash:previousPreviousHash,phase:prevPhase});
  previousHash=migrationAuditPacketHash(previous);
 }
 const allowed=sequence===0?'prepared':sequence===1?'snapshot-verified':sequence===2?'relay-observed':'blocked';
 refuse(phase===allowed);
 const state=await storage.probe(name);
 refuse(state==='present'||state==='absent');
 if(state==='present'){
  const actual=openMigrationAuditLabRecord(await storage.read(name),key,info,{sequence,phase,previousHash});
  refuse(JSON.stringify(actual.facts)===JSON.stringify(facts));
  return Object.freeze({created:false,sequence,phase,labOnly:true,liveRestoreAuthorized:false,legacyDeletionAuthorized:false});
 }
 const packet=sealMigrationAuditLabRecord({sequence,phase,previousHash,facts},key,info);
 await storage.write(name,packet);
 const recovered=openMigrationAuditLabRecord(await storage.read(name),key,info,{sequence,phase,previousHash});
 refuse(JSON.stringify(recovered.facts)===JSON.stringify(facts));
 return Object.freeze({created:true,sequence,phase,labOnly:true,liveRestoreAuthorized:false,legacyDeletionAuthorized:false});
}
async function predecessorHash(storage,key,info,sequence){
 // Rebuild the entire predecessor chain, so missing or substituted records
 // cannot be accepted even if their SHA-256 identifiers look well-formed.
 let prior='0'.repeat(64);
 for(let i=0;i<sequence;i++){
  const name=migrationAuditName(info.transactionId,i);
  refuse(await storage.probe(name)==='present');
  const packet=await storage.read(name);
  const phase=i===0?'prepared':i===1?'snapshot-verified':i===2?'relay-observed':'blocked';
  openMigrationAuditLabRecord(packet,key,info,{sequence:i,previousHash:prior,phase});
  prior=migrationAuditPacketHash(packet);
 }
 return prior;
}
