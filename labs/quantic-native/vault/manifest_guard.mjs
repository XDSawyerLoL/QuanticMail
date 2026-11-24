import {createHash,createPublicKey} from 'node:crypto';
import {assertVerifiedManifest} from './lib/quantic/manifest-node.mjs';
import {canonicalManifestText,mergeManifestState} from './lib/quantic/manifest-core.mjs';
const fail=()=>{throw Error('manifest refused')};
const hash=x=>createHash('sha256').update(x).digest('hex');
function pin(k){if(!k||k.kty!=='EC'||k.crv!=='P-256'||Object.keys(k).some(x=>!['kty','crv','x','y'].includes(x)))fail();for(const x of [k.x,k.y])if(typeof x!=='string'||! /^[A-Za-z0-9_-]{43}$/.test(x)||Buffer.from(x,'base64url').toString('base64url')!==x)fail();return hash(createPublicKey({key:k,format:'jwk'}).export({type:'spki',format:'der'}));}
function verify(m){assertVerifiedManifest(m);const p=m.payload;if(p.devices.length>64||p.revocations.length>1024||p.fingerprint.length!==32)fail();if(!/^[A-Za-z0-9+/]{86}==$/.test(m.signature)||Buffer.from(m.signature,'base64').toString('base64')!==m.signature)fail();pin(p.identityPublicKey);pin(p.identitySigningPublicKey);for(const d of p.devices){pin(d.publicKey);pin(d.deviceSigningPublicKey);}return p;}
export function evaluate({binding,current,incoming}){
 const p=verify(incoming); const {address,rootPin,deviceId,signPin,encPin}=binding;
 if(p.canonicalAddress!==address||pin(p.identitySigningPublicKey)!==rootPin)fail();
 if(current){const prev=verify(current);if(pin(prev.identityPublicKey)!==pin(p.identityPublicKey))fail();mergeManifestState(current,incoming);}
 const d=p.devices.find(x=>x.deviceId===deviceId);
 // A key change under an existing device ID is never accepted.
 if(d&&(pin(d.publicKey)!==encPin||pin(d.deviceSigningPublicKey)!==signPin))fail();
 return {active:Boolean(d)&&!p.revocations.some(x=>x.deviceId===deviceId),sequence:p.sequence,digest:hash(canonicalManifestText(p))};
}
if(process.argv[1]&&new URL(import.meta.url).pathname===process.argv[1]){try{let chunks=[],n=0;for await(const c of process.stdin){n+=c.length;if(n>600000)fail();chunks.push(c);}console.log(JSON.stringify(evaluate(JSON.parse(Buffer.concat(chunks)))));}catch{process.exitCode=1;}}
