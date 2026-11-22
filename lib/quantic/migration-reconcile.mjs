// Trusted local, read-only comparison of historical archive rows against a
// separately captured native recovery candidate. This never imports records,
// modifies the registry, activates prekeys, or grants permission to erase.
const groups=Object.freeze({messages:'id',contacts:'handle',prekeys:'preKeyId',outbox:'id'});
const refuse=(condition)=>{if(!condition)throw Error('Historical recovery reconciliation refused');};
function canonical(value,depth=0){
  refuse(depth<=32);
  if(value===null||typeof value==='string'||typeof value==='boolean')return JSON.stringify(value);
  if(typeof value==='number'){refuse(Number.isFinite(value));return JSON.stringify(value);}
  if(Array.isArray(value))return '['+value.map(v=>canonical(v,depth+1)).join(',')+']';
  refuse(value&&typeof value==='object'&&Object.getPrototypeOf(value)===Object.prototype);
  const keys=Object.keys(value).filter(k=>value[k]!==undefined).sort();
  refuse(keys.length<=256);
  return '{'+keys.map(k=>JSON.stringify(k)+':'+canonical(value[k],depth+1)).join(',')+'}';
}
function index(rows,key){
  refuse(Array.isArray(rows)&&rows.length<=10000);
  const out=new Map();
  for(const row of rows){
    refuse(row&&typeof row==='object'&&!Array.isArray(row));
    const id=row[key];
    refuse(typeof id==='string'&&id.length>0&&id.length<=512&&!out.has(id));
    out.set(id,canonical(row));
  }
  return out;
}
/**
 * Only pass decrypted historical records inside a trusted local process.
 * Candidate must be read back from the target, not the same archive object.
 * A matching result is NOT proof of durable writes or remote queue recovery.
 */
export function reconcileHistoricalCollections(archive,candidate){
  refuse(archive&&candidate&&archive!==candidate);
  const results={};
  let matched=true;
  for(const [name,key] of Object.entries(groups)){
    refuse(archive[name]!==candidate[name]);
    const sourceRows=new Set(archive[name]);
    refuse(candidate[name].every(row=>!sourceRows.has(row)));
    const original=index(archive[name],key),restored=index(candidate[name],key);
    let missing=0,modified=0,unexpected=0;
    for(const [id,value] of original){
      if(!restored.has(id))missing++;
      else if(restored.get(id)!==value)modified++;
    }
    for(const id of restored.keys())if(!original.has(id))unexpected++;
    const exact=missing===0&&modified===0&&unexpected===0;
    matched&&=exact;
    results[name]=Object.freeze({originalCount:original.size,candidateCount:restored.size,missing,modified,unexpected,exact});
  }
  return Object.freeze({
    collections:Object.freeze(results),historicalCollectionsMatch:matched,
    // A passing comparison cannot authorize cutover or revocation.
    durableTargetVerified:false,remoteQueueReconciled:false,
    nativeKeysImported:false,liveRegistrationAuthorized:false,
    liveRestoreAuthorized:false,legacyDeletionAuthorized:false,labOnly:true
  });
}
