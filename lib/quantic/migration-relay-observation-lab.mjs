// Read-only reconciliation of a laboratory Quantic Relay mailbox against a
// native recovery candidate. GET /pull and GET /receipts ONLY. No POST/ack,
// enrolment, token persistence, key activation or user/account migration.
// The current relay API exposes at most 100 rows; equal snapshots are only
// an observation, NEVER proof of a complete or atomic remote queue snapshot.
import {createHash} from 'node:crypto';
import {reconcileHistoricalCollections} from './migration-reconcile.mjs';

const deny=x=>{if(!x)throw Error('Read-only migration relay audit refused');};
const addr=/^[a-z0-9][a-z0-9._-]{2,31}~(?:[a-f0-9]{10}|[a-f0-9]{32})@quantic$/;
const device=/^d-[a-f0-9]{10}(?:[a-f0-9]{22})?$/;
const relayPin=/^[a-f0-9]{64}$/;
const boundedText=v=>typeof v==='string'&&v.length>0&&v.length<=512;
const MAX_BYTES=2*1024*1024;
const WINDOW=100;

function canonical(value,depth=0){
 deny(depth<=20);
 if(value===null||typeof value==='string'||typeof value==='boolean')return JSON.stringify(value);
 if(typeof value==='number'){deny(Number.isFinite(value));return JSON.stringify(value);}
 if(Array.isArray(value)){deny(value.length<=10000);return '['+value.map(v=>canonical(v,depth+1)).join(',')+']';}
 deny(value&&typeof value==='object'&&Object.getPrototypeOf(value)===Object.prototype);
 const keys=Object.keys(value).sort();deny(keys.length<=64);
 return '{'+keys.map(k=>JSON.stringify(k)+':'+canonical(value[k],depth+1)).join(',')+'}';
}
function sampleRows(rows,kind,context){
 deny(Array.isArray(rows)&&rows.length<=WINDOW);
 const byId=new Map();
 for(const entry of rows){
  deny(entry&&Object.getPrototypeOf(entry)===Object.prototype&&boundedText(entry.id)
   &&boundedText(entry.clientMessageId)&&!byId.has(entry.id));
  if(kind==='envelopes')deny(entry.to===context.canonicalAddress&&entry.toDeviceId===context.deviceId
    &&boundedText(entry.from)&&boundedText(entry.fromDeviceId)&&typeof entry.ciphertext==='string'
    &&typeof entry.iv==='string'&&entry.ephemeralPublicKey&&typeof entry.ephemeralPublicKey==='object');
  else deny(entry.from===context.canonicalAddress&&entry.fromDeviceId===context.deviceId
   &&boundedText(entry.to)&&boundedText(entry.toDeviceId)&&typeof entry.deliveredAt==='string');
  byId.set(entry.id,createHash('sha256').update(canonical(entry)).digest('hex'));
 }
 return byId;
}
function snapshot(s){
 deny(s&&s.labOnly===true&&relayPin.test(s.relayId)&&addr.test(s.canonicalAddress)
  &&device.test(s.deviceId)&&Array.isArray(s.envelopes)&&Array.isArray(s.receipts));
 return {envelopes:sampleRows(s.envelopes,'envelopes',s),receipts:sampleRows(s.receipts,'receipts',s)};
}
function delta(before,after){
 let missing=0,modified=0,added=0;
 for(const [id,digest] of before){if(!after.has(id))missing++;else if(after.get(id)!==digest)modified++;}
 for(const id of after.keys())if(!before.has(id))added++;
 return Object.freeze({beforeCount:before.size,afterCount:after.size,missing,modified,added,stable:missing===0&&modified===0&&added===0});
}
/** Only a fixed loopback endpoint, explicitly pinned relay instance, and a
 * supplied synthetic token are allowed. Token stays in process memory.
 * A network response without an independently verified relay identity
 * is NOT an attestation. No retry/fallback on failed HTTP authentication.
 */
export async function captureLoopbackRelayObservation({
 endpoint,canonicalAddress,deviceId,relayId,authToken,fetchImpl=fetch
}){
 deny(typeof endpoint==='string'&&typeof authToken==='string'&&authToken.length>=24&&authToken.length<=256
  &&addr.test(canonicalAddress)&&device.test(deviceId)&&relayPin.test(relayId)
  &&typeof fetchImpl==='function');
 const origin=new URL(endpoint);
 deny(origin.protocol==='http:'&&origin.hostname==='127.0.0.1'&&origin.pathname==='/'
  &&origin.search===''&&origin.hash===''&&origin.username===''&&origin.password===''
  &&origin.port!=='');
 const query='?handle='+encodeURIComponent(canonicalAddress)+'&deviceId='+encodeURIComponent(deviceId);
 async function read(path,property){
  const ctrl=new AbortController();
  // The caller owns cancellation/timeouts in any long-running workflow.
  const response=await fetchImpl(origin.origin+path+query,{
   method:'GET',headers:{authorization:'Bearer '+authToken},redirect:'error',
   cache:'no-store',signal:ctrl.signal
  });
  deny(response&&response.status===200&&response.ok===true);
  const chunks=[];let size=0;
  if(response.body){
   for await(const part of response.body){
    const b=Buffer.from(part);size+=b.length;deny(size<=MAX_BYTES);chunks.push(b);
   }
  }else{
   const b=Buffer.from(await response.arrayBuffer());size=b.length;deny(size<=MAX_BYTES);chunks.push(b);
  }
  deny(size>0);
  const data=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(Buffer.concat(chunks)));
  deny(data&&Object.getPrototypeOf(data)===Object.prototype&&Object.keys(data).length===1
   &&Array.isArray(data[property]));
  return data[property];
 }
 const envelopes=await read('/api/quantic/pull','envelopes');
 const receipts=await read('/api/quantic/receipts','receipts');
 const result={labOnly:true,relayId,canonicalAddress,deviceId,envelopes,receipts};
 snapshot(result);return structuredClone(result);
}
/** Exact comparison proves ONLY that the visible read-only windows are equal.
 * Local prekeys and unacknowledged outbox remain untouched. A second read
 * is necessary but cannot close an unsynchronized concurrent-write race.
 */
export function reconcileRelayObservationLab(before,after,source,candidate){
 const first=snapshot(before),second=snapshot(after);
 deny(before.relayId===after.relayId&&before.canonicalAddress===after.canonicalAddress
  &&before.deviceId===after.deviceId&&before!==after);
 const local=reconcileHistoricalCollections(source,candidate);
 const envelopes=delta(first.envelopes,second.envelopes);
 const receipts=delta(first.receipts,second.receipts);
 const visibleStable=envelopes.stable&&receipts.stable;
 const windowTruncated=before.envelopes.length===WINDOW||after.envelopes.length===WINDOW
  ||before.receipts.length===WINDOW||after.receipts.length===WINDOW;
 const historicalPrekeysPreserved=local.collections.prekeys.exact;
 const queuedOutboundPreserved=local.collections.outbox.exact;
 return Object.freeze({
  historicalCollectionsMatch:local.historicalCollectionsMatch,
  historicalPrekeysPreserved,queuedOutboundPreserved,
  observedRelayWindowStable:visibleStable,
  observedRelayWindowNotAtCap:!windowTruncated,
  envelopes,receipts,
  pendingIncomingVisible:after.envelopes.length,
  pendingReceiptsVisible:after.receipts.length,
  // No safe cutover, even for a stable empty window: no pagination,
  // provider-signed watermark, relay quorum or concurrent-write barrier.
  remoteQueueReconciled:false,durableTargetVerified:false,
  nativeKeysImported:false,liveRegistrationAuthorized:false,
  liveRestoreAuthorized:false,legacyDeletionAuthorized:false,labOnly:true
 });
}
