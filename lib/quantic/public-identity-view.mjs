// Display-only projection. Do not put a full LocalIdentity (JWK private
// keys, PQ secrets, bearer token) into React component state or debug tools.
// This is a mitigation, not isolation of private keys held in IndexedDB.
export function publicIdentityView(identity){
 if(!identity||typeof identity!=='object'||Array.isArray(identity)||
    typeof identity.handle!=='string'||typeof identity.address!=='string')
  throw Error('Invalid public identity display source');
 return Object.freeze({
  handle:identity.handle,address:identity.address,
  canonicalAddress:typeof identity.canonicalAddress==='string'?identity.canonicalAddress:undefined,
  fingerprint:typeof identity.fingerprint==='string'?identity.fingerprint:undefined
 });
}
