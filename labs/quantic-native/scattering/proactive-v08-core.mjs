/** Quantic Scattering V0.8 — offline-only cryptographic primitives.
 * Experimental, unaudited. Do not deploy, use with real secrets, or imply anonymity.
 */
import {
  createHash, getDiffieHellman, randomBytes, generateKeyPairSync,
  createPublicKey, diffieHellman, hkdfSync, createCipheriv, createDecipheriv,
  sign, verify,
} from 'node:crypto';

const P = BigInt('0x' + getDiffieHellman('modp15').getPrime('hex'));
export const Q = (P - 1n) / 2n;
export const N = 5;
export const T = 3;
const G = 2n;
const WIDTH = Math.ceil(P.toString(16).length / 2);
const hashInput = createHash('shake256', {outputLength: WIDTH}).update('Quantic Scattering Pedersen h v08 lab; independently hashed, no known discrete-log trapdoor').digest();
let H = (BigInt('0x' + hashInput.toString('hex')) % (P - 3n)) + 2n;
H = H * H % P;
if (H === 1n || H === G || modPow(G,Q,P) !== 1n || modPow(H,Q,P)!==1n) throw new Error('Invalid commitment group');
export const LAB_GROUP = {fieldBits:Q.toString(2).length, publicGroup:'RFC3526 MODP15, subgroup order q', subgroupVerified:true};

export function mod(n, m=Q) { const a=n%m;return a<0n?a+m:a; }
export function modPow(base, exponent, modulus=P) {
  let x=mod(base,modulus), e=exponent, out=1n;
  if(e<0n)throw new RangeError('negative exponent');
  while(e>0n){if(e&1n)out=out*x%modulus;x=x*x%modulus;e>>=1n;}
  return out;
}
export function sampleScalar() {
  let x;
  do { x=BigInt('0x'+randomBytes(WIDTH).toString('hex')); } while(x>=Q);
  return x;
}
export const scalarEncode=x=>{
  if(typeof x!=='bigint'||x<0n||x>=Q)throw new Error('invalid scalar');
  return x.toString(16).padStart(WIDTH*2,'0');
};
export const scalarDecode=x=>{
  if(typeof x!=='string'|| !new RegExp('^[0-9a-f]{'+(WIDTH*2)+'}$').test(x))throw new Error('invalid scalar encoding');
  const n=BigInt('0x'+x);
  if(n>=Q)throw new Error('scalar outside field');
  return n;
};
export const groupEncode=x=>{
  if(typeof x!=='bigint'||x<=0n||x>=P)throw new Error('invalid group element');
  return x.toString(16).padStart(WIDTH*2,'0');
};
export const groupDecode=x=>{
  if(typeof x!=='string'|| !new RegExp('^[0-9a-f]{'+(WIDTH*2)+'}$').test(x))throw new Error('invalid group encoding');
  const n=BigInt('0x'+x);
  if(n<=0n||n>=P||modPow(n,Q,P)!==1n)throw new Error('invalid subgroup commitment');
  return n;
};
export function commit(a,b){return modPow(G,a)*modPow(H,b)%P;}
export function evalPoly(coefficients,x){let y=0n, power=1n;for(const a of coefficients){y=mod(y+a*power);power=mod(power*BigInt(x));}return y;}
export function verifyShare(commitments,x,a,b){
  if(!Number.isInteger(x)||x<1||x>N)throw new Error('bad receiver index');
  if(commitments.length!==T)throw new Error('bad commitment count');
  const lhs=commit(a,b);
  let rhs=1n, power=1n;
  for(const encoded of commitments){rhs=rhs*modPow(groupDecode(encoded),power)%P;power=mod(power*BigInt(x));}
  return lhs===rhs;
}
export function addCommitments(columns){
  if(!columns.length||columns.some(row=>row.length!==T))throw new Error('inconsistent commitment matrix');
  return Array.from({length:T},(_,index)=>groupEncode(columns.reduce((acc,row)=>acc*groupDecode(row[index])%P,1n)));
}
export function zeroConstantProof(commitments,zeroBlind){
  return !!zeroBlind && groupDecode(commitments[0])===modPow(H,scalarDecode(zeroBlind));
}
export function lagrangeAtZero(points){
  if(!Array.isArray(points)||points.length!==T||new Set(points.map(p=>p.x)).size!==T)throw new Error('three distinct positions required');
  let answer=0n;
  for(const {x,y} of points){
    if(!Number.isInteger(x)||x<1||x>N||typeof y!=='bigint'||y<0n||y>=Q)throw new Error('invalid reconstruction share');
    let numerator=1n,denominator=1n;
    for(const other of points){if(other.x===x)continue;
      numerator=mod(numerator*(-BigInt(other.x)));
      denominator=mod(denominator*BigInt(x-other.x));
    }
    answer=mod(answer+y*numerator%Q*modPow(denominator,Q-2n,Q));
  }
  return answer;
}
export function publicDer(key){return key.export({format:'der',type:'spki'}).toString('base64');}
export const importPublic=b64=>createPublicKey({key:Buffer.from(b64,'base64'),format:'der',type:'spki'});
export const sha256=x=>createHash('sha256').update(typeof x==='string'?x:JSON.stringify(x)).digest('hex');
export const signJson=(obj,privateKey)=>sign(null,Buffer.from(JSON.stringify(obj)),privateKey).toString('base64');
export const verifyJson=(obj,signature,publicKey)=>typeof signature==='string'&&verify(null,Buffer.from(JSON.stringify(obj)),publicKey,Buffer.from(signature,'base64'));
export const newIdentity=()=>generateKeyPairSync('ed25519');
export const newTransport=()=>generateKeyPairSync('x25519');
export function encryptShare({a,b,ad,recipientPub}){
  const eph=newTransport();const shared=diffieHellman({privateKey:eph.privateKey,publicKey:importPublic(recipientPub)});
  const salt=randomBytes(32),iv=randomBytes(12);
  const key=Buffer.from(hkdfSync('sha256',shared,salt,Buffer.from('QS V08 share '+JSON.stringify(ad)),32));
  const cipher=createCipheriv('aes-256-gcm',key,iv,{authTagLength:16});
  cipher.setAAD(Buffer.from(JSON.stringify(ad)));
  const plaintext=Buffer.from(scalarEncode(a)+scalarEncode(b),'hex');
  const encrypted=Buffer.concat([cipher.update(plaintext),cipher.final()]);
  const envelope={eph:publicDer(eph.publicKey),salt:salt.toString('base64'),iv:iv.toString('base64'),
    ct:encrypted.toString('base64'),tag:cipher.getAuthTag().toString('base64')};
  plaintext.fill(0);key.fill(0);shared.fill(0);
  return envelope;
}
export function decryptShare({envelope,ad,receiverPriv}){
  if(!envelope||Object.keys(envelope).sort().join(',')!=='ct,eph,iv,salt,tag')throw new Error('malformed ciphertext envelope');
  const salt=Buffer.from(envelope.salt,'base64'),iv=Buffer.from(envelope.iv,'base64');
  const ct=Buffer.from(envelope.ct,'base64'),tag=Buffer.from(envelope.tag,'base64');
  if(salt.length!==32||iv.length!==12||tag.length!==16||ct.length!==WIDTH*2)throw new Error('malformed encrypted share length');
  const shared=diffieHellman({privateKey:receiverPriv,publicKey:importPublic(envelope.eph)});
  const key=Buffer.from(hkdfSync('sha256',shared,salt,Buffer.from('QS V08 share '+JSON.stringify(ad)),32));
  const decipher=createDecipheriv('aes-256-gcm',key,iv,{authTagLength:16});
  decipher.setAAD(Buffer.from(JSON.stringify(ad)));decipher.setAuthTag(tag);
  let plaintext;
  try {plaintext=Buffer.concat([decipher.update(ct),decipher.final()]);
    const a=scalarDecode(plaintext.subarray(0,WIDTH).toString('hex'));
    const b=scalarDecode(plaintext.subarray(WIDTH).toString('hex'));
    return {a,b};
  }finally{if(plaintext)plaintext.fill(0);key.fill(0);shared.fill(0);}
}
export function createContribution(mode){
  if(!['dkg','refresh'].includes(mode))throw new Error('invalid mode');
  const a=Array.from({length:T},()=>sampleScalar());const b=Array.from({length:T},()=>sampleScalar());
  if(mode==='refresh')a[0]=0n;
  return {a,b,commitments:a.map((value,i)=>groupEncode(commit(value,b[i]))),
    zeroBlind:mode==='refresh'?scalarEncode(b[0]):null};
}
export function validateRoundProof(proof,pub,epoch,mode){
  if(!proof||Object.keys(proof).sort().join(',')!=='commitments,dealer,epoch,mode,signature,zeroBlind')throw new Error('invalid dealer proof shape');
  const {signature,...body}=proof;
  if(!Number.isInteger(body.dealer)||body.dealer<1||body.dealer>N||body.epoch!==epoch||body.mode!==mode||!verifyJson(body,signature,pub))throw new Error('bad dealer proof signature or context');
  if(!Array.isArray(body.commitments)||body.commitments.length!==T)throw new Error('invalid commitments');
  body.commitments.forEach(groupDecode);
  if(mode==='refresh'){
    if(!zeroConstantProof(body.commitments,body.zeroBlind))throw new Error('non-zero refresh constant / missing zero proof');
  }else if(body.zeroBlind!==null)throw new Error('unexpected DKG zero proof');
  return true;
}
export function validateManifest(manifest,pub,epoch){
  if(!manifest||Object.keys(manifest).sort().join(',')!=='epoch,id,signature,transportPub')throw new Error('invalid manifest shape');
  const {signature,...body}=manifest;
  if(body.epoch!==epoch||!Number.isInteger(body.id)||body.id<1||body.id>N||!verifyJson(body,signature,pub))throw new Error('invalid signed recipient manifest');
  const key=importPublic(body.transportPub);
  if(key.asymmetricKeyType!=='x25519')throw new Error('bad transport public key');
  return true;
}
