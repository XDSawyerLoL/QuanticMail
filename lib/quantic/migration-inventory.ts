// Read-only migration inventory. Never returns key material, addresses or tokens.
// A successful inventory is NOT authorization to erase a historical identity.
export type MigrationInventory = {
  identityPresent:boolean;
  role:"root"|"secondary"|"unknown";
  canonicalFormat:"strong"|"legacy"|"unknown";
  rootSigningSecret:boolean;
  encryptionSecret:boolean;
  deviceSigningSecret:boolean;
  postQuantumSecrets:number;
  bearerPresent:boolean;
  manifestPresent:boolean;
  pendingDevice:boolean;
  prekeys:number;
  messages:number;
  outbox:number;
  contacts:number;
  canRemoveLegacyKeys:false;
  blockers:string[];
};
type Counts={pendingDevice:boolean;prekeys:number;messages:number;outbox:number;contacts:number};
function record(value:unknown):Record<string,unknown>{
  return value && typeof value==="object" && !Array.isArray(value) ? value as Record<string,unknown> : {};
}
function hasSecret(value:unknown){return typeof value==="string"&&value.length>0;}
export function summarizeMigration(identity:unknown,counts:Counts):MigrationInventory{
  const i=record(identity),pq=record(i.pqc);
  for(const count of [counts.prekeys,counts.messages,counts.outbox,counts.contacts]){
    if(!Number.isSafeInteger(count)||count<0)throw new Error("Inventaire incomplet.");
  }
  if(typeof counts.pendingDevice!=="boolean")throw new Error("Inventaire incomplet.");
  const addr=typeof i.canonicalAddress==="string"?i.canonicalAddress:"";
  const canonicalFormat=/^[a-z0-9][a-z0-9._-]{2,31}~[0-9a-f]{32}@quantic$/.test(addr)?"strong":/^[a-z0-9][a-z0-9._-]{2,31}~[0-9a-f]{10}@quantic$/.test(addr)?"legacy":"unknown";
  const role=i.role==="secondary"?"secondary":i.role==="root"?"root":"unknown";
  const blockers=["native-authorization-not-integrated","historical-key-recovery-not-verified","durable-registry-cutover-not-verified"];
  if(canonicalFormat!=="strong")blockers.push("canonical-address-needs-review");
  const postQuantumSecrets=Number(hasSecret(pq.mlKemPrivateKeyPkcs8))+Number(hasSecret(pq.mlDsaPrivateKeyPkcs8));
  if(postQuantumSecrets)blockers.push("post-quantum-key-migration-required");
  if(counts.pendingDevice)blockers.push("pending-pairing-must-be-resolved");
  if(counts.prekeys)blockers.push("historical-prekeys-must-be-preserved");
  if(counts.messages||counts.outbox||counts.contacts)blockers.push("local-mail-data-not-in-identity-backup");
  return {
    identityPresent:Object.keys(i).length>0,role,canonicalFormat,
    rootSigningSecret:hasSecret(record(i.signingPrivateKey).d),
    encryptionSecret:hasSecret(record(i.privateKey).d),
    deviceSigningSecret:hasSecret(record(i.deviceSigningPrivateKey).d),
    postQuantumSecrets,bearerPresent:hasSecret(i.authToken),
    manifestPresent:Boolean(i.manifest),pendingDevice:counts.pendingDevice,
    prekeys:counts.prekeys,messages:counts.messages,outbox:counts.outbox,contacts:counts.contacts,
    canRemoveLegacyKeys:false,blockers
  };
}
