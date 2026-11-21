// Read-only continuity of two public, independently attested devices.
// Both results must come from a trusted peer source, not user-supplied JSON.
// This is a migration precondition, NOT a registry write or cutover.
import {createHash} from 'node:crypto';
import {bindNativeContact} from './native-identity-bridge.mjs';
import {assertVerifiedManifest} from './manifest-node.mjs';
import {mergeManifestState} from './manifest-core.mjs';
const check=v=>{if(!v)throw Error('Migration continuity refused');};
const hex=/^[a-f0-9]{64}$/;
const device=/^d-[a-f0-9]{32}$/;
const addr=/^[a-z0-9][a-z0-9._-]{2,31}~[a-f0-9]{32}@quantic$/;
const sha=b=>createHash('sha256').update(b).digest('hex');
const pins=c=>[c.classicalSigningSpki,c.classicalEncryptionSpki,c.mlKemEncryptionSpki,c.mlDsaSigningSpki].map(v=>sha(Buffer.from(v,'base64')));
export async function checkMigrationContinuity({historicalManifest,address,oldDeviceId,newDeviceId,rootPin,pqRootPin,newDevicePins,peerSource}){
 check(addr.test(address)&&device.test(oldDeviceId)&&device.test(newDeviceId)&&oldDeviceId!==newDeviceId);
 check(hex.test(rootPin)&&hex.test(pqRootPin)&&Array.isArray(newDevicePins)&&newDevicePins.length===4&&newDevicePins.every(p=>hex.test(p))&&new Set(newDevicePins).size===4&&typeof peerSource==='function');
 const saved=assertVerifiedManifest(historicalManifest);
 check(saved.payload.canonicalAddress===address&&saved.payload.devices.some(d=>d.deviceId===oldDeviceId)&&!saved.payload.devices.some(d=>d.deviceId===newDeviceId));
 const [old,next]=await Promise.all([peerSource(address,oldDeviceId),peerSource(address,newDeviceId)]);
 const now=Date.now();
 const a=bindNativeContact(old.bundle,old.checkpoint,now),b=bindNativeContact(next.bundle,next.checkpoint,now);
 check(a.address===address&&b.address===address&&a.deviceId===oldDeviceId&&b.deviceId===newDeviceId);
 for(const k of ['manifestSequence','profileSequence','manifestDigest','profileDigest','rootPin','pqRootPin'])check(old.checkpoint[k]===next.checkpoint[k]);
 check(old.checkpoint.rootPin===rootPin&&old.checkpoint.pqRootPin===pqRootPin&&old.checkpoint.manifestSequence>saved.payload.sequence);
 const current=assertVerifiedManifest(next.bundle.manifest);
 mergeManifestState(saved,current);
 const p=saved.payload.devices.find(d=>d.deviceId===oldDeviceId),q=current.payload.devices.find(d=>d.deviceId===oldDeviceId),n=current.payload.devices.find(d=>d.deviceId===newDeviceId);
 const equalPoint=(x,y)=>x?.kty===y?.kty&&x?.crv===y?.crv&&x?.x===y?.x&&x?.y===y?.y;
 check(q&&n?.kind==='linked'&&equalPoint(p.publicKey,q.publicKey)&&equalPoint(p.deviceSigningPublicKey,q.deviceSigningPublicKey));
 const priorPins=pins(a),candidatePins=pins(b);
 check(candidatePins.every((v,i)=>v===newDevicePins[i]&&!priorPins.includes(v)));
 return Object.freeze({sameIdentity:true,previousDeviceActive:true,newDeviceAttested:true,manifestSequence:old.checkpoint.manifestSequence,profileSequence:old.checkpoint.profileSequence,expires:Math.min(old.checkpoint.expires,next.checkpoint.expires),liveRestoreAuthorized:false,legacyDeletionAuthorized:false});
}
