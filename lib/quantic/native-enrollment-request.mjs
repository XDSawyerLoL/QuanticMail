// Trusted controller domain validator for a native device enrollment proof.
// Never use a browser request to call this function directly; the broker
// independently checks the exact challenge and requires local approval.
import {createHash} from 'node:crypto';
const hash=s=>createHash('sha256').update(s).digest('hex');
const pin=/^[a-f0-9]{64}$/,address=/^[a-z0-9][a-z0-9._-]{2,31}~[a-f0-9]{32}@quantic$/;
const check=v=>{if(!v)throw Error('Native enrollment challenge refused');};
export function validateNativeEnrollmentRequest(challenge,{signingPin,encryptionPin,encryptionPublicKey,expectedAddress,expectedRootPin,now=Date.now()}){
 check(typeof challenge==='string'&&Buffer.byteLength(challenge,'utf8')<=2048);
 check(pin.test(signingPin)&&pin.test(encryptionPin));
 check(Number.isSafeInteger(now)&&now>=0);
 let a;try{a=JSON.parse(challenge);}catch{check(false);}
 check(Array.isArray(a)&&a.length===11&&JSON.stringify(a)===challenge);
 const [domain,canonical,rootPin,sequence,manifestDigest,deviceId,signPin,encPin,label,nonce,expires]=a;
 check(domain==='quantic-native-enrollment-lab-v1'
  &&address.test(canonical)&&pin.test(rootPin)
  &&Number.isSafeInteger(sequence)&&sequence>=1&&sequence<Number.MAX_SAFE_INTEGER
  &&pin.test(manifestDigest)
  &&/^[a-f0-9]{64}$/.test(nonce)
  &&typeof label==='string'&&label.length>=2&&label.length<=48
  &&label.trim()===label
  &&Number.isSafeInteger(expires)&&expires>now&&expires-now<=30000);
 const e=encryptionPublicKey;
 check(e?.kty==='EC'&&e.crv==='P-256'&&!Object.hasOwn(e,'d')
  &&typeof e.x==='string'&&typeof e.y==='string');
 const expectedId='d-'+hash('P-256:'+e.x+':'+e.y).slice(0,32);
 check(deviceId===expectedId&&signPin===signingPin&&encPin===encryptionPin);
 // Address and historical owner pin MUST come from trusted controller context,
 // not from the challenge itself, where an adversary may substitute them.
 if(expectedAddress!==undefined)check(expectedAddress===canonical&&address.test(expectedAddress));
 if(expectedRootPin!==undefined)check(expectedRootPin===rootPin&&pin.test(expectedRootPin));
 return Object.freeze({canonicalAddress:canonical,deviceId,rootPin,sequence,expires,
  // No private key, bearer credential, or registration authority returned.
  labOnly:true,registrationAuthorized:false,legacyDeletionAuthorized:false});
}
