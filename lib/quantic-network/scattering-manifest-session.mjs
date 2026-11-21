// Experimental: no production wiring. The authority callback MUST be independently trusted.
import { createHash, createPublicKey, generateKeyPairSync, randomBytes, sign, verify, diffieHellman, hkdfSync, createCipheriv, createDecipheriv } from 'node:crypto';
import { assertVerifiedManifest } from '../quantic/manifest-node.mjs';
import { canonicalManifestText, activeDevices } from '../quantic/manifest-core.mjs';
const DOMAIN='quantic-scattering-manifest-lab-v1', TTL=300000, LEASE=60000, LIMIT=150000;
const requireOk=(ok,msg)=>{if(!ok)throw Error(msg)};
const hash=b=>createHash('sha256').update(b).digest('hex');
const encode=x=>Buffer.from(JSON.stringify(x));
const der=k=>k.export({type:'spki',format:'der'});
const jwk=k=>createPublicKey({key:k,format:'jwk'});
export const pin=k=>hash(der(k));
export const manifestDigest=m=>hash(canonicalManifestText(m.payload));
const b64=b=>Buffer.from(b).toString('base64url');
function decode(s,n){requireOk(typeof s==='string'&&s.length<=2048&&/^[A-Za-z0-9_-]+$/.test(s),'invalid encoding');const b=Buffer.from(s,'base64url');requireOk(b64(b)===s&&(!n||b.length===n),'invalid size');return b;}
function snap(id,read,t){
  const a=read(id.address);requireOk(a&&Number.isSafeInteger(a.validUntil)&&a.validUntil>t&&a.validUntil<=t+LEASE,'authority lease unavailable');
  const m=assertVerifiedManifest(a.manifest),p=m.payload,digest=manifestDigest(m);
  requireOk(p.canonicalAddress===id.address&&p.fingerprint.length===32&&id.deviceId.length===34,'identity mismatch or legacy identifier');
  requireOk(a.sequence===p.sequence&&a.digest===digest,'authority snapshot mismatch');
  const root=pin(jwk(p.identitySigningPublicKey));requireOk(root===id.rootPin,'root pin mismatch');
  const d=activeDevices(m).find(x=>x.deviceId===id.deviceId);requireOk(d,'device revoked or absent');
  const key=jwk(d.deviceSigningPublicKey),device=pin(key);
  requireOk(device===id.devicePin&&device!==root&&device!==pin(jwk(p.identityPublicKey))&&device!==pin(jwk(d.publicKey)),'device key mismatch or not separated');
  requireOk(Date.parse(p.issuedAt)<=t&&Date.parse(d.issuedAt)<=t,'future authorization');
  return {key,sequence:p.sequence,digest};
}
const helloData=h=>({domain:h.domain,role:h.role,address:h.address,deviceId:h.deviceId,sequence:h.sequence,digest:h.digest,nonce:h.nonce,ephemeral:h.ephemeral});
export function startManifestSession({role,local,peer,devicePrivate,readAuthority,clock=Date.now,labOnly}){
  requireOk(labOnly===true,'lab opt-in required');requireOk(role==='initiator'||role==='responder','invalid role');
  local=structuredClone(local);peer=structuredClone(peer);requireOk(local.devicePin!==peer.devicePin,'reflection');
  const started=clock(),a=snap(local,readAuthority,started),b=snap(peer,readAuthority,started);
  requireOk(pin(createPublicKey(devicePrivate))===local.devicePin,'wrong device private key');
  let eph=generateKeyPairSync('x25519'),remote,transcript,sendKey,recvKey,epoch,closed=false,finished=false,last=started,counter=0;
  const seen=new Set(),other=role==='initiator'?'responder':'initiator';
  const hello={domain:DOMAIN,role,address:local.address,deviceId:local.deviceId,sequence:a.sequence,digest:a.digest,nonce:b64(randomBytes(32)),ephemeral:b64(der(eph.publicKey))};
  function close(){closed=true;sendKey?.fill(0);recvKey?.fill(0);sendKey=recvKey=eph=remote=transcript=null;seen.clear();}
  function current(){try{const t=clock();requireOk(!closed&&Number.isSafeInteger(t)&&t>=last&&t-started<TTL,'closed, clock rollback or expired');last=t;const x=snap(local,readAuthority,t),y=snap(peer,readAuthority,t);requireOk(x.digest===a.digest&&y.digest===b.digest,'manifest changed');return t;}catch(e){close();throw e;}}
  function proofData(r){return encode({domain:DOMAIN,transcript,signer:r});}
  function nonce(n){const v=Buffer.alloc(12);v.writeBigUInt64BE(BigInt(n),4);return v;}
  function aad(n){return encode([DOMAIN,epoch,n]);}
  return {hello:structuredClone(hello),close,
    prove(h){try{current();requireOk(!transcript&&!finished,'proof already issued');h=helloData(h);requireOk(h.domain===DOMAIN&&h.role===other&&h.address===peer.address&&h.deviceId===peer.deviceId&&h.sequence===b.sequence&&h.digest===b.digest,'wrong peer or stale hello');decode(h.nonce,32);remote=createPublicKey({key:decode(h.ephemeral),format:'der',type:'spki'});requireOk(remote.asymmetricKeyType==='x25519','wrong ephemeral key');transcript={initiator:role==='initiator'?hello:h,responder:role==='responder'?hello:h};return b64(sign('sha256',proofData(role),{key:devicePrivate,dsaEncoding:'ieee-p1363'}));}catch(e){close();throw e;}},
    finish(proof){try{current();requireOk(transcript&&!finished,'not negotiating');requireOk(verify('sha256',proofData(other),{key:b.key,dsaEncoding:'ieee-p1363'},decode(proof,64)),'invalid peer proof');const secret=diffieHellman({privateKey:eph.privateKey,publicKey:remote});try{epoch=hash(encode(transcript));const derive=label=>Buffer.from(hkdfSync('sha256',secret,Buffer.from(epoch,'hex'),Buffer.from(DOMAIN+':'+label),32));sendKey=derive(role);recvKey=derive(other);finished=true;return epoch;}finally{secret.fill(0);eph=remote=transcript=null;}}catch(e){close();throw e;}},
    seal(data){current();requireOk(finished&&Buffer.isBuffer(data)&&data.length<=4096&&counter<LIMIT,'invalid send');const n=counter++,c=createCipheriv('aes-256-gcm',sendKey,nonce(n));c.setAAD(aad(n));return {epoch,n,body:Buffer.concat([c.update(data),c.final(),c.getAuthTag()])};},
    open(frame){current();requireOk(finished&&frame?.epoch===epoch&&Number.isSafeInteger(frame.n)&&frame.n>=0&&frame.n<LIMIT&&!seen.has(frame.n)&&Buffer.isBuffer(frame.body)&&frame.body.length>=16&&frame.body.length<=4112,'invalid epoch or replay');const c=createDecipheriv('aes-256-gcm',recvKey,nonce(frame.n));c.setAAD(aad(frame.n));c.setAuthTag(frame.body.subarray(-16));const plain=Buffer.concat([c.update(frame.body.subarray(0,-16)),c.final()]);seen.add(frame.n);return plain;}
  };
}
