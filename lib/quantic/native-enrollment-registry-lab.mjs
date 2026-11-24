// One independent authority, laboratory only. Never activate mail policy
// or register production accounts. Each authority must run its own challenge.
import {createHash,createPublicKey,sign,verify} from 'node:crypto';
import {open,lstat,realpath} from 'node:fs/promises';
import {constants} from 'node:fs';
import {join,resolve} from 'node:path';
import {issueNativePossessionChallenge} from './native-possession-challenge.mjs';
const check=x=>{if(!x)throw Error('Native enrollment registry refused');};
const sha=b=>createHash('sha256').update(b).digest('hex');
const hex=/^[a-f0-9]{64}$/;
const addr=/^[a-z0-9][a-z0-9._-]{2,31}~[a-f0-9]{32}@quantic$/;
const dev=/^d-[a-f0-9]{32}$/;
const format='quantic-native-enrollment-receipt-lab/v1';
const fields=['format','authorityPin','address','deviceId','candidateDigest','rootPin','pqRootPin','approvedPinsDigest','challengeSha256','acceptedAt'];
const pinFields=['address','deviceId','rootPin','pqRootPin','quorumPin','signingPin','encryptionPin','kemPin','dsaPin','controllerPublic'];
function scope(candidate,expected){
 check(candidate?.format==='quantic-native-owner-candidate-lab/v1'&&candidate.labOnly===true&&candidate.registrationAuthorized===false&&candidate.devicePossessionVerified===false&&candidate.policyCandidate?.active===false);
 const p=candidate.policyCandidate;
 check(addr.test(p.address)&&dev.test(p.deviceId)&&p.address===expected.address&&p.deviceId===expected.deviceId&&p.rootPin===expected.rootPin&&p.pqRootPin===expected.pqRootPin);
 check(pinFields.slice(2,-1).every(k=>typeof expected[k]==='string'&&hex.test(expected[k])));
 check(typeof expected.controllerPublic==='string'&&/^[A-Za-z0-9_-]{43}$/.test(expected.controllerPublic));
 return {address:p.address,deviceId:p.deviceId,candidateDigest:sha(JSON.stringify(candidate)),rootPin:p.rootPin,pqRootPin:p.pqRootPin,approvedPinsDigest:sha(JSON.stringify(pinFields.map(k=>expected[k])))};
}
function canonical(r){
 check(r&&Object.keys(r).length===fields.length+1&&fields.every(k=>Object.hasOwn(r,k))&&Object.hasOwn(r,'signature'));
 check(r.format===format&&addr.test(r.address)&&dev.test(r.deviceId)&&Number.isSafeInteger(r.acceptedAt)&&r.acceptedAt>0);
 for(const k of ['authorityPin','candidateDigest','rootPin','pqRootPin','approvedPinsDigest','challengeSha256'])check(typeof r[k]==='string'&&hex.test(r[k]));
 return Buffer.from(JSON.stringify(fields.map(k=>r[k])));
}
function verifyReceipt(r,key,expected){
 const bytes=canonical(r);
 check(r.authorityPin===sha(key.export({type:'spki',format:'der'})));
 check(Object.keys(expected).every(k=>r[k]===expected[k]));
 check(typeof r.signature==='string'&&/^[A-Za-z0-9_-]{86}$/.test(r.signature));
 const sig=Buffer.from(r.signature,'base64url');
 check(sig.length===64&&sig.toString('base64url')===r.signature&&verify(null,bytes,key,sig));
 return r;
}
export function verifyNativeEnrollmentReceipts(receipts,trusted,candidate,expected){
 check(Array.isArray(receipts)&&receipts.length>=3&&receipts.length<=4&&Array.isArray(trusted)&&trusted.length===4);
 const target=scope(candidate,expected),keys=new Map();
 for(const t of trusted){
  check(typeof t.publicKey==='string'&&/^[A-Za-z0-9_-]{59}$/.test(t.publicKey)&&hex.test(t.pin)&&!keys.has(t.pin));
  const raw=Buffer.from(t.publicKey,'base64url');
  check(raw.length===44&&raw.toString('base64url')===t.publicKey&&sha(raw)===t.pin);
  const k=createPublicKey({key:raw,format:'der',type:'spki'});check(k.asymmetricKeyType==='ed25519');keys.set(t.pin,k);
 }
 const seen=new Set(),challenges=new Set();
 for(const r of receipts){
  check(keys.has(r?.authorityPin)&&!seen.has(r.authorityPin)&&!challenges.has(r.challengeSha256));
  verifyReceipt(r,keys.get(r.authorityPin),target);
  seen.add(r.authorityPin);challenges.add(r.challengeSha256);
 }
 return Object.freeze({...target,status:'independent-enrollment-receipt-quorum-lab',authorityCount:seen.size,labOnly:true,registrationAuthorized:false,mailPolicyActive:false});
}
export async function createNativeEnrollmentRegistryLab({directory,authorityKey,authorityPin,clock=Date.now,labOnly}){
 check(labOnly===true&&process.platform==='linux'&&typeof directory==='string'&&resolve(directory)===directory&&await realpath(directory)===directory);
 const st=await lstat(directory);check(st.isDirectory()&&st.uid===process.getuid()&&(st.mode&0o077)===0);
 check(authorityKey?.type==='private'&&authorityKey.asymmetricKeyType==='ed25519');
 const key=createPublicKey(authorityKey);
 check(hex.test(authorityPin)&&sha(key.export({type:'spki',format:'der'}))===authorityPin);
 const pathFor=address=>join(directory,'identity-'+sha(address)+'.json');
 async function readback(candidate,expected){
  const target=scope(candidate,expected);
  const fd=await open(pathFor(target.address),constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
  try{
   const s=await fd.stat();check(s.isFile()&&s.nlink===1&&s.uid===process.getuid()&&(s.mode&0o077)===0&&s.size>1&&s.size<=65536);
   const b=Buffer.alloc(s.size+1);let n=0;
   while(n<b.length){const r=await fd.read(b,n,b.length-n,null);if(!r.bytesRead)break;n+=r.bytesRead;}
   check(n===s.size);
   const stored=JSON.parse(b.subarray(0,n).toString('utf8'));
   check(stored&&Object.keys(stored).length===2&&sha(JSON.stringify(stored.candidate))===target.candidateDigest);
   return Object.freeze(verifyReceipt(stored.receipt,key,target));
  }finally{await fd.close();}
 }
 async function begin(candidate,expected,{operatorApproved=false}={}){
  // Caller must be the trusted independent operator, not an HTTP body.
  check(operatorApproved===true);
  const snapshot=structuredClone(candidate),pins=structuredClone(expected),target=scope(snapshot,pins);
  const path=pathFor(target.address);
  try{await lstat(path);throw Error('Address already reserved');}catch(e){if(e?.code!=='ENOENT')throw e;}
  const challenge=issueNativePossessionChallenge(snapshot,pins,{clock});
  return Object.freeze({challenge:challenge.challenge,challengeSha256:challenge.challengeSha256,expires:challenge.expires,close:challenge.close,
   async commit(response){
    const proof=challenge.verify(response);
    check(proof.devicePossessionVerified===true&&proof.candidateDigest===target.candidateDigest);
    const acceptedAt=clock();check(Number.isSafeInteger(acceptedAt)&&acceptedAt>0&&acceptedAt<challenge.expires);
    const receipt={format,authorityPin,...target,challengeSha256:challenge.challengeSha256,acceptedAt,signature:''};
    receipt.signature=sign(null,canonical(receipt),authorityKey).toString('base64url');
    const bytes=Buffer.from(JSON.stringify({candidate:snapshot,receipt}));
    check(bytes.length<=65536);
    // Exclusive create protects against concurrent replacement of the same
    // canonical address. An incomplete file is a hard refusal, not a retry.
    const fd=await open(path,'wx',0o600);
    try{await fd.writeFile(bytes);await fd.sync();}finally{await fd.close();}
    const parent=await open(directory,'r');try{await parent.sync();}finally{await parent.close();}
    return readback(snapshot,pins);
   }});
 }
 return Object.freeze({begin,readback});
}
