import {createHash,createPublicKey,randomBytes,verify} from 'node:crypto';
import {canonicalManifestText,mergeManifestState} from './manifest-core.mjs';
import {assertVerifiedManifest} from './manifest-node.mjs';
const check=(ok,msg)=>{if(!ok)throw Error(msg)};
const hash=s=>createHash('sha256').update(s).digest('hex');
const point=k=>{check(k?.kty==='EC'&&k.crv==='P-256'&&!('d' in k),'public P-256 required');const p=createPublicKey({key:k,format:'jwk'}).export({format:'jwk'});return {kty:p.kty,crv:p.crv,x:p.x,y:p.y}};
const pin=k=>hash(createPublicKey({key:point(k),format:'jwk'}).export({type:'spki',format:'der'}));
const digest=m=>hash(canonicalManifestText(m.payload));
export function prepareNativeEnrollment({manifest,expectedRootPin,signingKey,encryptionKey,label,clock=Date.now,labOnly}){
  check(labOnly===true,'laboratory only');assertVerifiedManifest(manifest);
  const old=structuredClone(manifest),p=old.payload;
  check(pin(p.identitySigningPublicKey)===expectedRootPin,'root pin mismatch');
  check(typeof label==='string'&&label===label.trim()&&label.length>=2&&label.length<=48,'invalid label');
  const s=point(signingKey),e=point(encryptionKey),pins=[pin(s),pin(e)];
  const existing=[p.identitySigningPublicKey,p.identityPublicKey,...p.devices.flatMap(d=>[d.publicKey,d.deviceSigningPublicKey])].map(pin);
  check(pins[0]!==pins[1]&&pins.every(k=>!existing.includes(k)),'key reuse');
  const deviceId='d-'+hash(`P-256:${e.x}:${e.y}`).slice(0,32);
  check(!p.revocations.some(x=>x.deviceId===deviceId),'revoked device');
  const issued=clock();check(Number.isSafeInteger(issued),'invalid clock');
  const device={deviceId,label,publicKey:e,deviceSigningPublicKey:s,kind:'linked',issuedAt:new Date(issued).toISOString()};
  const challenge=JSON.stringify(['quantic-native-enrollment-lab-v1',p.canonicalAddress,expectedRootPin,p.sequence,digest(old),deviceId,pins[0],pins[1],label,randomBytes(32).toString('hex'),issued+30000]);
  let state='pending',last=issued;
  function guard(){const now=clock();if(!Number.isSafeInteger(now)||now<last||now>=issued+30000){state='closed';throw Error('expired or clock rollback')}last=now;}
  return {challenge,deviceId,
    authorize(signature,approved){guard();check(state==='pending','not pending');check(approved===true,'local approval required');check(typeof signature==='string'&&/^[0-9a-f]{128}$/.test(signature)&&verify('sha256',Buffer.from(challenge),{key:createPublicKey({key:s,format:'jwk'}),dsaEncoding:'ieee-p1363'},Buffer.from(signature,'hex')),'invalid device proof');state='authorized';return {...structuredClone(p),sequence:p.sequence+1,devices:[...structuredClone(p.devices),structuredClone(device)],issuedAt:device.issuedAt};},
    confirm(next){guard();check(state==='authorized','not authorized');assertVerifiedManifest(next);mergeManifestState(old,next);const expected={...p,sequence:p.sequence+1,devices:[...p.devices,device],issuedAt:device.issuedAt};check(canonicalManifestText(next.payload)===canonicalManifestText(expected),'unexpected signed update');state='closed';return {canonicalAddress:p.canonicalAddress,deviceId,sequence:next.payload.sequence,digest:digest(next),safeToRemoveOldKeys:false,hardwareAttested:false};}
  };
}
