/**
 * Quantic Scattering V1.5 research-only mutually authenticated session handshake.
 * Classical primitives: pinned Ed25519 signing identities + ephemeral X25519 KEX.
 * NOT post-quantum. Signing keys must be pinned through an authenticated channel.
 * The wire format intentionally omits device identities, but does not conceal timing.
 */
import {
  createHash, createHmac, createPublicKey, diffieHellman, generateKeyPairSync,
  hkdfSync, randomBytes, sign, timingSafeEqual, verify,
} from 'node:crypto';

const PREFIX=Buffer.from('QS-SCATTERING-HANDSHAKE-V15\0', 'utf8');
const INIT=Buffer.from([0x49]), RESP=Buffer.from([0x52]), FINISH=Buffer.from([0x46]);
const ZERO=Buffer.alloc(0);
const SECRET_STATES=new WeakMap();
const keyEncoding={format:'der',type:'spki'};
const derive=(ikm,salt,info,length)=>Buffer.from(hkdfSync('sha256',ikm,salt,Buffer.concat([PREFIX,Buffer.from(info)]),length));

function okBytes(buffer, length, name){
  if(!Buffer.isBuffer(buffer)||buffer.length!==length)throw new Error(`${name}: invalid length`);
}
function assertSigningKey(key, kind){
  if(!key||key.type!==kind||key.asymmetricKeyType!=='ed25519')throw new Error(`Expected ${kind} Ed25519 identity key`);
}
function ephRaw(publicKey){return publicKey.export(keyEncoding);}
function signedInit(nonce,eph){
  okBytes(nonce,32,'initiator nonce');okBytes(eph,44,'initiator key');
  return Buffer.concat([PREFIX,INIT,nonce,eph]);
}
function signedResponse(initBody,nonce,eph){
  okBytes(nonce,32,'responder nonce');okBytes(eph,44,'responder key');
  return Buffer.concat([PREFIX,RESP,initBody,nonce,eph]);
}
function rawPublicKey(der){
  okBytes(der,44,'X25519 public key');
  const key=createPublicKey({key:der,...keyEncoding});
  if(key.asymmetricKeyType!=='x25519'||!ephRaw(key).equals(der))throw new Error('Invalid ephemeral key');
  return key;
}
function verifySignature(pub,body,signature){
  assertSigningKey(pub,'public');okBytes(signature,64,'identity signature');
  if(!verify(null,body,pub,signature))throw new Error('Peer signing identity not authenticated');
}
function state(role,secret){
  const handle=Object.freeze({version:15,role});
  SECRET_STATES.set(handle,{...secret,used:false});
  return handle;
}
function claim(handle,role){
  const secret=SECRET_STATES.get(handle);
  if(!secret||handle.role!==role||secret.used)throw new Error('Handshake state invalid or already used');
  secret.used=true;
  return secret;
}
function computeSession(role,privateEph,peerDer,transcript){
  const peer=rawPublicKey(peerDer);
  const shared=diffieHellman({privateKey:privateEph,publicKey:peer});
  if(shared.equals(Buffer.alloc(shared.length)))throw new Error('Invalid shared secret');
  const hash=createHash('sha256').update(transcript).digest();
  const root=derive(shared,hash,'session-root',32);
  const a=derive(root,hash,'initiator->responder',32);
  const b=derive(root,hash,'responder->initiator',32);
  const confirmationKey=derive(root,hash,'key-confirmation',32);
  const sessionId=derive(root,hash,'session-identifier',16);
  root.fill(0);shared.fill(0);
  return {
    session:{sessionId,sendMasterSecret:role==='initiator'?a:b,receiveMasterSecret:role==='initiator'?b:a,
      version:15,keyAgreement:'X25519',identitySignature:'Ed25519',postQuantum:false},
    confirmationKey,
  };
}
function keyConfirmation(key,transcript){
  return createHmac('sha256',key).update(PREFIX).update(FINISH).update(transcript).digest();
}
/** Requires provisioned, pinned peerSigningPublicKey. Never transmit private keys. */
export function initiateSession({localSigningPrivateKey,peerSigningPublicKey}={}){
  assertSigningKey(localSigningPrivateKey,'private');assertSigningKey(peerSigningPublicKey,'public');
  const {privateKey,publicKey}=generateKeyPairSync('x25519');
  const nonce=randomBytes(32),ephemeralPublicKey=ephRaw(publicKey),body=signedInit(nonce,ephemeralPublicKey);
  const hello={nonce,ephemeralPublicKey,signature:sign(null,body,localSigningPrivateKey)};
  return {handle:state('initiator',{privateKey,body,peerSigningPublicKey}),hello};
}
export function respondSession({localSigningPrivateKey,peerSigningPublicKey,hello}={}){
  assertSigningKey(localSigningPrivateKey,'private');assertSigningKey(peerSigningPublicKey,'public');
  if(!hello)throw new Error('Missing hello');
  const initBody=signedInit(hello.nonce,hello.ephemeralPublicKey);
  verifySignature(peerSigningPublicKey,initBody,hello.signature);
  rawPublicKey(hello.ephemeralPublicKey);
  const {privateKey,publicKey}=generateKeyPairSync('x25519');
  const nonce=randomBytes(32),ephemeralPublicKey=ephRaw(publicKey);
  const transcript=signedResponse(initBody,nonce,ephemeralPublicKey);
  const response={nonce,ephemeralPublicKey,signature:sign(null,transcript,localSigningPrivateKey)};
  return {handle:state('responder',{privateKey,peerDer:Buffer.from(hello.ephemeralPublicKey),transcript}),response};
}
export function finishInitiatorSession(handle,response){
  const s=claim(handle,'initiator');
  if(!response)throw new Error('Missing response');
  const transcript=signedResponse(s.body,response.nonce,response.ephemeralPublicKey);
  verifySignature(s.peerSigningPublicKey,transcript,response.signature);
  const keys=computeSession('initiator',s.privateKey,response.ephemeralPublicKey,transcript);
  const finish={confirmation:keyConfirmation(keys.confirmationKey,transcript)};
  keys.confirmationKey.fill(0);
  return {session:keys.session,finish};
}
export function finishResponderSession(handle,finish){
  const s=claim(handle,'responder');
  const keys=computeSession('responder',s.privateKey,s.peerDer,s.transcript);
  try{
    if(!finish)throw new Error('Missing key confirmation');
    okBytes(finish.confirmation,32,'Key confirmation');
    const expected=keyConfirmation(keys.confirmationKey,s.transcript);
    if(!timingSafeEqual(expected,finish.confirmation))throw new Error('Invalid session key confirmation');
    return keys.session;
  }finally{
    keys.confirmationKey.fill(0);
  }
}
export function publicSigningKeyFingerprint(publicKey){
  assertSigningKey(publicKey,'public');
  return createHash('sha256').update(publicKey.export(keyEncoding)).digest('hex');
}