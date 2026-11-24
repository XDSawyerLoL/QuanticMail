// Owner-side one-shot challenge for an INACTIVE native identity candidate.
// No registration, policy activation, or network service.
import {createHash,createHmac,createPublicKey,generateKeyPairSync,diffieHellman,encapsulate,randomBytes,timingSafeEqual,verify} from 'node:crypto';
import {bindNativeContact} from './native-identity-bridge.mjs';
const check=x=>{if(!x)throw Error('Native enrollment possession refused');};
const sha=b=>createHash('sha256').update(b).digest('hex');
const hex=/^[a-f0-9]{64}$/;
const domain='quantic-native-enrollment-possession-lab/v1';
const mac=(key,data)=>createHmac('sha256',key).update(data).digest();
const spki=(s)=>createPublicKey({key:Buffer.from(s,'base64'),format:'der',type:'spki'});
const point=k=>{const j=k.export({format:'jwk'});return Buffer.concat([Buffer.from([4]),Buffer.from(j.x,'base64url'),Buffer.from(j.y,'base64url')]);};
function decode(s,n){check(typeof s==='string'&&s.length<=Math.ceil(n*4/3)&&/^[A-Za-z0-9_-]+$/.test(s));const b=Buffer.from(s,'base64url');check(b.length===n&&b.toString('base64url')===s);return b;}
export function issueNativePossessionChallenge(candidate,expected,{clock=Date.now}={}){
 const now=clock();
 check(Number.isSafeInteger(now)&&candidate?.format==='quantic-native-owner-candidate-lab/v1'&&candidate.labOnly===true&&candidate.registrationAuthorized===false&&candidate.devicePossessionVerified===false&&candidate.policyCandidate?.active===false);
 const p=candidate.policyCandidate;
 check(p.address===expected.address&&p.deviceId===expected.deviceId&&p.rootPin===expected.rootPin&&p.pqRootPin===expected.pqRootPin);
 const c=bindNativeContact(candidate.bundle,{...p,expires:now+10000},now);
 for(const [field,pin] of [['classicalSigningSpki','signingPin'],['classicalEncryptionSpki','encryptionPin'],['mlKemEncryptionSpki','kemPin'],['mlDsaSigningSpki','dsaPin']])check(hex.test(expected[pin])&&sha(Buffer.from(c[field],'base64'))===expected[pin]);
 check(hex.test(expected.quorumPin));decode(expected.controllerPublic,32);
 const candidateDigest=sha(Buffer.from(JSON.stringify(candidate)));
 const nonce=randomBytes(32).toString('hex'),expires=now+180000;
 const ephemeral=generateKeyPairSync('ec',{namedCurve:'prime256v1'});
 const ec=diffieHellman({privateKey:ephemeral.privateKey,publicKey:spki(c.classicalEncryptionSpki)});
 const {sharedKey:pq,ciphertext}=encapsulate(spki(c.mlKemEncryptionSpki));
 const challenge=JSON.stringify([domain,p.address,p.deviceId,expected.signingPin,expected.encryptionPin,expected.kemPin,expected.dsaPin,expected.quorumPin,expected.controllerPublic,candidateDigest,nonce,expires,point(ephemeral.publicKey).toString('base64url'),ciphertext.toString('base64url')]);
 const raw=Buffer.from(challenge),combined=Buffer.concat([ec,pq]);
 let key,proof;
 try{key=mac(Buffer.from(domain),combined);proof=mac(key,raw);}
 finally{ec.fill(0);pq.fill(0);combined.fill(0);key?.fill(0);}
 let used=false;
 return Object.freeze({challenge,challengeSha256:sha(raw),candidateDigest,expires,
  close(){used=true;proof.fill(0);},
  verify(response){
   check(!used);used=true;
   try{
    const at=clock();check(Number.isSafeInteger(at)&&at>=now&&at<expires);
    check(response&&Object.keys(response).length===4&&response.status==='native-possession-lab-proof'&&response.challengeSha256===sha(raw));
    // Both signatures authenticate the same fixed-domain challenge and
    // possession MAC. The MAC itself never leaves the native device.
    const transcript=Buffer.concat([Buffer.from(domain+'\0'),raw,Buffer.from([0]),proof]);
    check(verify('sha256',transcript,{key:spki(c.classicalSigningSpki),dsaEncoding:'ieee-p1363'},decode(response.classicalSignature,64)));
    check(verify(null,transcript,spki(c.mlDsaSigningSpki),decode(response.pqSignature,3309)));
    return Object.freeze({status:'native-device-four-key-possession-verified',candidateDigest,address:p.address,deviceId:p.deviceId,devicePossessionVerified:true,registrationAuthorized:false,labOnly:true});
   }finally{proof.fill(0);}
  }
 });
}
