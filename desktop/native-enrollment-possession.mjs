// Laboratory operator only. A fresh, signed challenge proves possession of
// both device signing keys AND both encryption keys. No relay mutation,
// policy approval, authority grant or credentials are produced automatically.
import {createHash,createPublicKey,generateKeyPairSync,diffieHellman,encapsulate,hkdfSync,randomBytes,createCipheriv,sign,verify,timingSafeEqual} from 'node:crypto';
import {verifyNativeEnrollmentRequest} from './native-enrollment-claim.mjs';
import {enrollmentRosterPin,enrollmentRequestDigest,enrollmentVoteTranscript,ENROLLMENT_VOTE_TTL} from './native-enrollment-quorum.mjs';
const check=x=>{if(!x)throw Error('Enrollment possession refused');};
const hash=x=>createHash('sha256').update(x).digest('hex');
const pin=/^[a-f0-9]{64}$/;
const suite='QNT-HYB-P256-MLKEM768-HKDFSHA256-AES256GCM-1';
const domain='quantic-native-enrollment-possession-lab/v1';
const responseDomain='quantic-native-enrollment-possession-response-lab/v1';
const keyDER=k=>k.export({format:'der',type:'spki'});
const ec=j=>createPublicKey({key:j,format:'jwk'});
const pq=j=>createPublicKey({key:Buffer.from(j,'base64url'),format:'der',type:'spki'});
const canonical=x=>Buffer.from(JSON.stringify(x));
const transcript=c=>canonical([domain,c.authorityPin,c.quorumPin,c.address,c.deviceId,c.manifestDigest,c.profileDigest,c.nonce,String(c.expires),
 c.envelope.cryptoSuite,c.envelope.keyMode,c.envelope.classicalEphemeralPublicKey.kty,c.envelope.classicalEphemeralPublicKey.crv,
 c.envelope.classicalEphemeralPublicKey.x,c.envelope.classicalEphemeralPublicKey.y,c.envelope.pqKemCiphertext,c.envelope.iv,c.envelope.ciphertext]);
function exact(o,keys){check(o&&typeof o==='object'&&!Array.isArray(o)&&Object.keys(o).length===keys.length&&keys.every(k=>Object.hasOwn(o,k)));}
function decode(s,n,enc='base64url'){check(typeof s==='string'&&s.length<=Math.ceil(n/3)*4);const b=Buffer.from(s,enc);check(b.length===n&&b.toString(enc)===s);return b;}
export function prepareNativePossessionChallenge(request,{quorumPin,authorityKey,expectedAuthorityPin,trusted,rosterPin,clock=Date.now}={}){
 const issued=clock();
 const claim=verifyNativeEnrollmentRequest(request,{quorumPin,now:issued});
 check(authorityKey?.type==='private'&&authorityKey.asymmetricKeyType==='ed25519'&&pin.test(expectedAuthorityPin??''));
 const operator=keyDER(createPublicKey(authorityKey));check(hash(operator)===expectedAuthorityPin);
 // Opt-in approval mode. Never accept a roster supplied by the applicant.
 const voting=trusted!==undefined||rosterPin!==undefined;
 if(voting){check(typeof rosterPin==='string'&&enrollmentRosterPin(trusted)===rosterPin&&trusted.some(t=>t.pin===expectedAuthorityPin));}
 const requestDigest=enrollmentRequestDigest(request,claim);
 const md=request.claim.manifest.payload.devices[0],pd=request.claim.profile.payload.devices[0];
 const signKey=ec(md.deviceSigningPublicKey),dsaKey=pq(pd.mlDsaPublicKeySpki);
 const eph=generateKeyPairSync('ec',{namedCurve:'prime256v1'}),j=eph.publicKey.export({format:'jwk'});
 const nonce=randomBytes(32).toString('hex'),id='enroll-'+nonce;
 // Reuse the existing hybrid envelope KDF and AES-GCM implementation, in an
 // enrollment-only message context, never submitted to the mailbox.
 const ctx=[ 'quantic-hybrid-envelope-context-v1',suite,id,claim.address,claim.deviceId,claim.address,claim.deviceId].join('\n');
 const z=diffieHellman({privateKey:eph.privateKey,publicKey:ec(md.publicKey)});
 const kem=encapsulate(pq(pd.mlKemPublicKeySpki));
 const shared=Buffer.concat([z,kem.sharedKey]);z.fill(0);kem.sharedKey.fill(0);
 const key=Buffer.from(hkdfSync('sha256',shared,Buffer.from(hash('quantic-hybrid-kdf-salt-v1\n'+ctx),'hex'),Buffer.from(ctx),32));shared.fill(0);
 const secret=randomBytes(32),expected=Buffer.from(hash(secret),'hex'),iv=randomBytes(12);
 let ciphertext;
 try{const g=createCipheriv('aes-256-gcm',key,iv);g.setAAD(Buffer.from(ctx+'\nquantic-aes-gcm-aad-v1'));ciphertext=Buffer.concat([g.update(secret),g.final(),g.getAuthTag()]);}
 finally{key.fill(0);secret.fill(0);}
 const c={format:domain,authorityPin:expectedAuthorityPin,authorityPublic:operator.toString('base64url'),quorumPin,address:claim.address,deviceId:claim.deviceId,
 manifestDigest:claim.manifestDigest,profileDigest:claim.profileDigest,nonce,expires:issued+300000,
 envelope:{cryptoSuite:suite,keyMode:'hybrid-static-fallback',classicalEphemeralPublicKey:{kty:j.kty,crv:j.crv,x:j.x,y:j.y},
 pqKemCiphertext:Buffer.from(kem.ciphertext).toString('base64url'),iv:iv.toString('base64url'),ciphertext:ciphertext.toString('base64url')}};
 c.signature=sign(null,transcript(c),authorityKey).toString('base64url');
 const challengeHash=hash(transcript(c));
 let used=false;
 return Object.freeze({
  challenge:structuredClone(c),
  verify(response,{approved=false,approveEnrollment=false}={}){
   check(!used);used=true;
   try{
    const now=clock();check(Number.isSafeInteger(now)&&now>=issued&&now<c.expires&&approved===true);
    exact(response,['format','challengeHash','secretHash','p256Signature','mlDsaSignature']);
    check(response.format===responseDomain&&response.challengeHash===challengeHash&&pin.test(response.secretHash));
    check(timingSafeEqual(Buffer.from(response.secretHash,'hex'),expected));
    const proof=canonical([responseDomain,challengeHash,response.secretHash]);
    check(verify('sha256',proof,{key:signKey,dsaEncoding:'ieee-p1363'},decode(response.p256Signature,64,'base64')));
    check(verify(null,proof,dsaKey,decode(response.mlDsaSignature,3309)));
    // Only a proposal for THIS operator's independent policy review. Existing
    // signed renewal, durable snapshot and quorum checks remain mandatory.
    let vote;
    if(approveEnrollment===true){
     check(voting);
     const payload={format:'quantic-native-enrollment-vote-lab/v1',authorityPin:expectedAuthorityPin,rosterPin,requestDigest,
      proofDigest:hash(canonical([challengeHash,response.secretHash,response.p256Signature,response.mlDsaSignature])),issuedAt:now,expires:now+ENROLLMENT_VOTE_TTL,decision:'approve'};
     vote=Object.freeze({payload:Object.freeze(payload),signature:sign(null,enrollmentVoteTranscript(payload),authorityKey).toString('base64url')});
    }
    return Object.freeze({...(vote?{vote}:{}),status:'device-possession-verified-pending-authority-renewal',labOnly:true,authorityPin:expectedAuthorityPin,
      policyCandidate:Object.freeze({address:claim.address,deviceId:claim.deviceId,rootPin:claim.rootPin,pqRootPin:claim.pqRootPin,
      manifestSequence:1,profileSequence:1,manifestDigest:claim.manifestDigest,profileDigest:claim.profileDigest,active:false}),
      remotelyEnrolled:false,mailAuthorized:false});
   }finally{expected.fill(0);}
  }
 });
}
