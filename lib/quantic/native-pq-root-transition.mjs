// Offline, read-only chain-of-custody preflight for PQ identity root changes.
// A stolen legacy P-256 key MUST NOT suffice to replace a previously pinned
// ML-DSA root. No registration, key import, revocation or destructive action.
import {createHash,createPublicKey} from 'node:crypto';
import {assertVerifiedManifest} from './manifest-node.mjs';
import {mergeManifestState} from './manifest-core.mjs';
import {canonicalCryptoProfileText} from './crypto-profile-core.mjs';
import {verifyCryptoProfile} from './crypto-profile-node.mjs';

const refuse=condition=>{if(!condition)throw Error('Native PQ root continuity refused');};
const HEX=/^[0-9a-f]{64}$/;
const sha=value=>createHash('sha256').update(value).digest('hex');

function pqPin(spki) {
  refuse(typeof spki==='string'&&/^[A-Za-z0-9_-]+$/.test(spki));
  const der=Buffer.from(spki,'base64url');
  refuse(der.length===1974&&der.toString('base64url')===spki);
  const key=createPublicKey({key:der,format:'der',type:'spki'});
  refuse(key.asymmetricKeyType==='ml-dsa-65' &&
    key.export({format:'der',type:'spki'}).equals(der));
  return sha(der);
}
function p256Pin(jwk) {
  refuse(jwk&&jwk.kty==='EC'&&jwk.crv==='P-256'&&!Object.hasOwn(jwk,'d'));
  const key=createPublicKey({key:jwk,format:'jwk'});
  refuse(key.asymmetricKeyType==='ec'&&key.asymmetricKeyDetails?.namedCurve==='prime256v1');
  return sha(key.export({type:'spki',format:'der'}));
}

/**
 * previousProfileDigest, historicalRootPin and previousPqRootPin MUST be
 * obtained independently of BOTH the archive and the network response.
 *
 * If the predecessor root was already compromised, this alone cannot restore
 * trust; a separate externally governed identity recovery is required.
 */
export function verifyNativePqRootTransition({
  previousIdentityManifest, previousCryptoProfile,
  currentIdentityManifest, currentCryptoProfile,
  previousProfileDigest, historicalRootPin,
  previousPqRootPin, expectedCurrentPqRootPin,
}) {
  refuse([previousProfileDigest,historicalRootPin,previousPqRootPin,expectedCurrentPqRootPin]
    .every(value=>typeof value==='string'&&HEX.test(value)));
  const prevManifest=assertVerifiedManifest(previousIdentityManifest);
  const currentManifest=assertVerifiedManifest(currentIdentityManifest);
  mergeManifestState(prevManifest,currentManifest); // manifest rollback/fork check
  refuse(prevManifest.payload.canonicalAddress===currentManifest.payload.canonicalAddress);
  refuse(p256Pin(prevManifest.payload.identitySigningPublicKey)===historicalRootPin);
  refuse(p256Pin(currentManifest.payload.identitySigningPublicKey)===historicalRootPin);

  // Verify historical profile with historical manifest, not a newer manifest
  // whose revoked devices might invalidate an otherwise authentic ancestor.
  const prev=verifyCryptoProfile(previousCryptoProfile,prevManifest);
  refuse(prev.payload.policy==='hybrid-required');
  refuse(sha(canonicalCryptoProfileText(prev.payload))===previousProfileDigest);
  refuse(pqPin(prev.payload.identityMlDsaPublicKeySpki)===previousPqRootPin);
  const next=verifyCryptoProfile(currentCryptoProfile,currentManifest,prev);
  refuse(next.payload.policy==='hybrid-required');
  refuse(next.payload.sequence>prev.payload.sequence);
  refuse(next.payload.identityManifestSequence===currentManifest.payload.sequence);
  refuse(pqPin(next.payload.identityMlDsaPublicKeySpki)===expectedCurrentPqRootPin);
  return Object.freeze({
    previousProfilePinned:true,
    previousPqRootPinned:true,
    authenticatedPqRootContinuity:true,
    previousProfileSequence:prev.payload.sequence,
    nextProfileSequence:next.payload.sequence,
    nextPqRootPin:expectedCurrentPqRootPin,
    liveRegistrationAuthorized:false,
    liveRestoreAuthorized:false,
    legacyDeletionAuthorized:false,
    physicalDeviceTested:false,
    independentAuditorApproved:false,
  });
}
