/* Trusted local Node controller only. Never expose via HTTP or Electron renderer IPC.
 * Requires independently provisioned compact-manifest-quorum laboratory vault.
 */
import {spawn} from 'node:child_process';
import {createHash,createPublicKey,createPrivateKey,sign,verify} from 'node:crypto';
import {readFile,stat} from 'node:fs/promises';
import {isAbsolute} from 'node:path';
const hash=b=>createHash('sha256').update(b).digest();
const hex=b=>hash(b).toString('hex');
const pinRE=/^[a-f0-9]{64}$/;
const check=(ok,msg)=>{if(!ok)throw new Error(msg)};
function b64(s,min,max,encoding='base64url'){
  check(typeof s==='string'&&s.length<=Math.ceil(max/3)*4,'invalid encoding');
  const b=Buffer.from(s,encoding);
  check(b.length>=min&&b.length<=max&&b.toString(encoding)===s,'invalid encoding');
  return b;
}
function publicPoint(s){
  const p=b64(s,65,65);check(p[0]===4,'invalid point');
  const jwk={kty:'EC',crv:'P-256',x:p.subarray(1,33).toString('base64url'),y:p.subarray(33).toString('base64url')};
  const key=createPublicKey({key:jwk,format:'jwk'});
  return {jwk,key,pin:hex(key.export({format:'der',type:'spki'}))};
}
export function controllerFrame(nonce,seq,body,key){
  check(Buffer.isBuffer(nonce)&&nonce.length===32&&Number.isInteger(seq)&&seq>=1&&seq<=256,'invalid session');
  const raw=Buffer.from(JSON.stringify(body));check(raw.length<=32767,'request too large');
  const count=Buffer.alloc(4);count.writeUInt32BE(seq);
  const digest=hash(Buffer.concat([Buffer.from('quantic-vault-controller-lab/v1\0'),nonce,count,raw]));
  return JSON.stringify({seq,body:raw.toString('base64url'),sig:sign(null,digest,key).toString('base64url')})+'\n';
}
export function normalizeClassicalEnvelope(e){
  check(e&&typeof e==='object'&&!Array.isArray(e),'invalid envelope');
  // Require explicit choice of classical static mode; never downgrade prekey or hybrid.
  check(e.keyMode==='static-fallback'&&!e.preKeyId&&!e.cryptoSuite&&!e.hybrid&&!e.pqc&&!e.kemCiphertext&&!e.mlKemCiphertext&&!e.pqKemCiphertext&&!e.classicalEphemeralPublicKey,'unsupported envelope mode');
  const j=e.ephemeralPublicKey;
  check(j?.kty==='EC'&&j.crv==='P-256'&&!('d' in j),'invalid public key');
  const p=Buffer.concat([Buffer.from([4]),b64(j.x,32,32),b64(j.y,32,32)]);
  const {jwk}=publicPoint(p.toString('base64url'));
  b64(e.iv,12,12,'base64');b64(e.ciphertext,16,8208,'base64');
  return {ciphertext:e.ciphertext,iv:e.iv,ephemeralPublicKey:jwk};
}
export async function connectNativeVault({binary,binarySha256,vault,journal,quorum,controllerKeyFile,signingPin,encryptionPin,labOnly}){
  check(labOnly===true&&process.platform==='linux','Linux laboratory only');
  for(const p of [binary,vault,journal,quorum,controllerKeyFile])check(typeof p==='string'&&isAbsolute(p),'absolute path required');
  check([binarySha256,signingPin,encryptionPin].every(p=>pinRE.test(p)),'trusted pins required');
  const ks=await stat(controllerKeyFile);
  check(ks.isFile()&&(ks.mode&0o077)===0&&ks.uid===process.getuid(),'controller key must be private');
  const key=createPrivateKey(await readFile(controllerKeyFile));
  check(key.asymmetricKeyType==='ed25519','invalid controller key');
  check(hex(await readFile(binary))===binarySha256,'broker executable mismatch');
  const app=createPublicKey(key).export({format:'jwk'}).x;
  const child=spawn(binary,['--broker-software-compact-manifest-quorum-lab',vault,signingPin,encryptionPin,app,journal,quorum],{shell:false,stdio:['pipe','pipe','inherit']});
  let buf=Buffer.alloc(0),waiter=null,closed=false,busy=false,seq=0,nonce,signing;
  function fail(){
    if(closed)return;closed=true;child.kill();if(waiter){const w=waiter;waiter=null;clearTimeout(w.timer);w.reject(Error('native vault unavailable'));}
  }
  child.on('error',fail);child.on('exit',fail);child.stdin.on('error',fail);child.stdout.on('error',fail);
  child.stdout.on('data',chunk=>{
    if(closed)return;
    if(buf.length+chunk.length>32768){fail();return;}
    buf=Buffer.concat([buf,chunk]);const end=buf.indexOf(10);
    if(end<0)return;
    if(!waiter||end!==buf.length-1){fail();return;}
    const w=waiter;waiter=null;clearTimeout(w.timer);
    const line=buf.subarray(0,end);buf=Buffer.alloc(0);
    try{const r=JSON.parse(line.toString('utf8'));check(r&&typeof r==='object'&&!Array.isArray(r),'invalid reply');w.resolve(r);}catch{w.reject(Error('invalid native reply'));fail();}
  });
  function receive(){
    check(!closed&&!waiter,'native vault unavailable');
    return new Promise((resolve,reject)=>{waiter={resolve,reject,timer:setTimeout(fail,45000)};});
  }
  async function call(body){
    check(!closed&&!busy,'native vault unavailable or busy');busy=true;
    try{const frame=controllerFrame(nonce,++seq,body,key);const reply=receive();child.stdin.write(frame);const r=await reply;check(r.ok===true,'native operation refused');return r;}
    finally{busy=false;}
  }
  try{
    const hello=await receive();nonce=b64(hello.session,32,32);
    const p=await call({op:'public'});signing=publicPoint(p.signing);const enc=publicPoint(p.encryption);
    check(signing.pin===signingPin&&enc.pin===encryptionPin,'native vault point mismatch');
    return Object.freeze({
      publicKeys:Object.freeze({signing:Object.freeze(signing.jwk),encryption:Object.freeze(enc.jwk)}),
      async openStatic(envelope){
        const r=await call({op:'mail-open-static-lab',mail:normalizeClassicalEnvelope(envelope)});
        try{return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(b64(r.message,1,8192)));}
        catch{fail();throw Error('invalid native plaintext');}
      },
      async signEnrollment(challenge){
        // Only the exact native enrollment domain. Broker independently verifies all fields and local consent.
        const a=JSON.parse(challenge);
        check(Array.isArray(a)&&a.length===11&&a[0]==='quantic-native-enrollment-lab-v1'&&a[6]===signingPin&&a[7]===encryptionPin&&Buffer.byteLength(challenge)<=2048,'invalid enrollment');
        const r=await call({op:'enroll-proof',enrollment:challenge,approved:true});
        check(typeof r.enrollmentProof==='string'&&/^[0-9a-f]{128}$/.test(r.enrollmentProof)&&verify('sha256',Buffer.from(challenge),{key:signing.key,dsaEncoding:'ieee-p1363'},Buffer.from(r.enrollmentProof,'hex')),'invalid enrollment proof');
        return r.enrollmentProof;
      },
      close(){fail();}
    });
  }catch(error){fail();throw error;}
}
