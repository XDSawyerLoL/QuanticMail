/* Trusted local Node controller only. Never expose via HTTP or Electron renderer IPC.
 * Requires independently provisioned compact-manifest-quorum laboratory vault.
 */
import {spawn} from 'node:child_process';
import {createHash,createPublicKey,createPrivateKey,sign,verify,randomBytes,generateKeyPairSync} from 'node:crypto';
import {readFile,stat} from 'node:fs/promises';
import {isAbsolute,win32} from 'node:path';
import {createWindowsNativeStorage} from './native-windows-storage.mjs';
import {validateNativeEnrollmentRequest} from '../lib/quantic/native-enrollment-request.mjs';
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
export async function connectNativeVault({binary,binarySha256,vault,journal,quorum,controllerKeyFile,controllerPublic,signingPin,encryptionPin,labOnly,pqMode,windowsLab,windowsScattering,guiWindowsApproval=false}){
  const sealed=windowsScattering?.credentialMode==='vault-sealed-v1';
  if(sealed)check(guiWindowsApproval===true&&windowsScattering.token===undefined&&windowsScattering.address===pqMode?.address&&windowsScattering.deviceId===pqMode?.deviceId,'sealed mailbox configuration required');
  const windows=process.platform==='win32';
  check(guiWindowsApproval===false||guiWindowsApproval===true,'invalid native GUI approval mode');
  if(guiWindowsApproval)check(windows&&windowsLab?.enabled===true&&pqMode?.enabled===true,'Windows GUI approval requires explicitly scoped PQ lab');
  check(labOnly===true&&(process.platform==='linux'||windows&&windowsLab?.enabled===true&&pqMode?.enabled===true),'Explicit native laboratory only');
  for(const p of [binary,vault,journal,quorum,controllerKeyFile])check(typeof p==='string'&&isAbsolute(p),'absolute path required');
  check([binarySha256,signingPin,encryptionPin].every(p=>pinRE.test(p)),'trusted pins required');
  let storage;
  if(windows){
    check(Number(process.versions.node.split('.')[0])>=24,'Node 24 required');
    storage=await createWindowsNativeStorage({binary,binarySha256,dir:windowsLab.dir});
    for(const [path,n] of [[vault,'classical.vault'],[journal,'journal.log'],[quorum,'quorum.json'],[controllerKeyFile,sealed?'controller.vault':'controller.pem'],[pqMode.sidecar,'pq.vault'],[pqMode.contactDirectory,'contacts.json']])check(path===win32.join(storage.dir,n),'Windows vault layout mismatch');
  }else{
    const ks=await stat(controllerKeyFile);
    check(ks.isFile()&&(ks.mode&0o077)===0&&ks.uid===process.getuid(),'controller key must be private');
  }
  let key;
  if(sealed){b64(controllerPublic,32,32);key=generateKeyPairSync('ed25519').privateKey;}
  else{const secret=await (storage?storage.read(controllerKeyFile):readFile(controllerKeyFile));try{key=createPrivateKey(secret);}finally{secret.fill(0);}}
  check(key.asymmetricKeyType==='ed25519','invalid controller key');
  check(hex(await readFile(binary))===binarySha256,'broker executable mismatch');
  const app=createPublicKey(key).export({format:'jwk'}).x;
  let peerSource,bridge,contacts;
  if(pqMode!==undefined){
    check(pqMode?.enabled===true&&Number(process.versions.node.split('.')[0])>=24,'Node 24 PQ laboratory required');
    for(const path of [pqMode.sidecar,pqMode.contactDirectory])check(typeof path==='string'&&isAbsolute(path),'absolute PQ paths required');
    check([pqMode.kemPin,pqMode.dsaPin,pqMode.rootPin].every(p=>pinRE.test(p)),'independent PQ pins required');
    const {createAttestedPeerSource}=await import('./native-attested-peer.mjs');
    bridge=await import('../lib/quantic/native-identity-bridge.mjs');
    if(!sealed)peerSource=await createAttestedPeerSource(pqMode.authority,storage?{read:storage.read}:{});
    else check(pqMode.authority?.clientKeyFile===win32.join(storage.dir,'peer-checkpoint-key.vault')&&Array.isArray(pqMode.authority.authorities)&&pqMode.authority.authorities.length===4,'sealed checkpoint configuration required');
    if(storage){contacts=JSON.parse((await storage.read(pqMode.contactDirectory)).toString('utf8'));}
    else{const ds=await stat(pqMode.contactDirectory);check(ds.isFile()&&ds.uid===process.getuid()&&(ds.mode&0o077)===0&&ds.size<=131072,'private contact directory required');contacts=JSON.parse(await readFile(pqMode.contactDirectory,'utf8'));}
    check(Array.isArray(contacts)&&contacts.length>=1&&contacts.length<=32,'invalid contacts');
  }
  const args=windows?[sealed?'--broker-windows-pq-enrolled-mail-gui-lab':guiWindowsApproval?'--broker-windows-pq-gui-lab':'--broker-windows-pq-quorum-lab',storage.dir,app,signingPin,encryptionPin,pqMode.address,pqMode.deviceId,pqMode.kemPin,pqMode.dsaPin,pqMode.rootPin,...(sealed?[windowsScattering.endpoint]:[])]:pqMode?['--broker-software-pq-quorum-lab',vault,signingPin,encryptionPin,app,journal,quorum,pqMode.sidecar,pqMode.address,pqMode.deviceId,pqMode.kemPin,pqMode.dsaPin,pqMode.rootPin,'auto',pqMode.contactDirectory]:['--broker-software-compact-manifest-quorum-lab',vault,signingPin,encryptionPin,app,journal,quorum];
  if(storage)await storage.verifyBinary();
  const child=spawn(binary,args,{shell:false,stdio:['pipe','pipe',guiWindowsApproval?'ignore':'inherit'],...(storage?{cwd:win32.dirname(binary),env:storage.env,windowsHide:guiWindowsApproval}:{})});
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
  async function signNativeEnrollment(challenge){
    // Broker independently validates the same scope and prompts for the
    // approval locally. Never trust renderer-supplied permission flags.
    // The native PQ migration path refuses challenges without the original
    // ownership SPKI pin obtained independently of the untrusted archive.
    if(pqMode)check(pinRE.test(pqMode.historicalRootPin),'trusted historical ownership root pin required');
    validateNativeEnrollmentRequest(challenge,{
      signingPin,encryptionPin,encryptionPublicKey:enc?.jwk,
      expectedAddress:pqMode?.address,
      expectedRootPin:pqMode?.historicalRootPin
    });
    const r=await call({op:'enroll-proof',enrollment:challenge,approved:true});
    check(typeof r.enrollmentProof==='string'&&/^[0-9a-f]{128}$/.test(r.enrollmentProof)
      &&verify('sha256',Buffer.from(challenge),
      {key:signing.key,dsaEncoding:'ieee-p1363'},
      Buffer.from(r.enrollmentProof,'hex')),'invalid enrollment proof');
    return r.enrollmentProof;
  }
  let enc;
  try{
    const hello=await receive();nonce=b64(hello.session,32,32);
    if(sealed){
      const root=createPublicKey({key:{kty:'OKP',crv:'Ed25519',x:controllerPublic},format:'jwk'});
      const digest=hash(Buffer.concat([Buffer.from('quantic-native-controller-session-lab/v1\0'),nonce,b64(app,32,32)]));
      check(verify(null,digest,root,b64(hello.delegation,64,64)),'native controller delegation refused');
    }
    const p=await call({op:'public'});signing=publicPoint(p.signing);enc=publicPoint(p.encryption);
    check(signing.pin===signingPin&&enc.pin===encryptionPin,'native vault point mismatch');
    if(pqMode){
      check(p.backend===(windows?'windows-software-pq-quorum-lab':'software-pq-quorum-lab'),'wrong native backend');
      const pq=await call({op:'pq-public-lab'});
      check(hex(b64(pq.pqKem,1206,1206))===pqMode.kemPin&&hex(b64(pq.pqDsa,1974,1974))===pqMode.dsaPin,'native PQ pin mismatch');
      const ownKeys={classicalSigningSpki:signing.key.export({format:'der',type:'spki'}).toString('base64'),classicalEncryptionSpki:enc.key.export({format:'der',type:'spki'}).toString('base64'),mlKemEncryptionSpki:Buffer.from(pq.pqKem,'base64url').toString('base64'),mlDsaSigningSpki:Buffer.from(pq.pqDsa,'base64url').toString('base64')};
      const sameKeys=(a,b)=>Object.keys(ownKeys).every(k=>a?.[k]===b?.[k]);
      if(sealed){
        const {verifyCheckpointQuorum}=await import('../lib/quantic/native-checkpoint-authority.mjs');
        peerSource=async(address,deviceId)=>{
          const request={address,deviceId,nonce:randomBytes(32).toString('hex'),expires:Date.now()+15000};
          const r=await call({op:'native-mailbox-lab',mailboxOp:'checkpoint',mailboxBody:request});
          const result=r.mailboxResult;
          const checkpoint=verifyCheckpointQuorum(result?.attestations,pqMode.authority.authorities,request);
          return {bundle:result.bundle,checkpoint,contact:bridge.bindNativeContact(result.bundle,checkpoint)};
        };
      }
      async function peers(c){
        // The authenticated native pipe allows one outstanding frame at a time.
        const [from,to]=sealed?[await peerSource(c.from,c.fromDeviceId),await peerSource(c.to,c.toDeviceId)]:await Promise.all([peerSource(c.from,c.fromDeviceId),peerSource(c.to,c.toDeviceId)]);
        const own=c.from===pqMode.address&&c.fromDeviceId===pqMode.deviceId?from:to;
        const other=own===from?to:from;
        check(own.contact.address===pqMode.address&&own.contact.deviceId===pqMode.deviceId&&own.checkpoint.pqRootPin===pqMode.rootPin&&sameKeys(own.contact,ownKeys),'own identity mismatch');
        const matches=contacts.filter(x=>x.address===other.contact.address&&x.deviceId===other.contact.deviceId);
        check(matches.length===1&&sameKeys(matches[0],other.contact)&&matches[0].expires>Date.now(),'contact key mismatch');
        return {from,to};
      }
      function verified(record,pair){
        return bridge.verifyNativeWire(record,pair.from.bundle,pair.from.checkpoint,pair.to.bundle,pair.to.checkpoint);
      }
      let mailBusy=false;
      async function exclusive(fn){check(!mailBusy&&!closed,'native session unavailable');mailBusy=true;try{return await fn();}catch(e){fail();throw e;}finally{mailBusy=false;}}
      const mailbox=sealed?(await import('./native-mailbox-client.mjs')).createNativeMailboxClient(windowsScattering,{transport:(op,body)=>exclusive(async()=>{
        const r=await call({op:'native-mailbox-lab',mailboxOp:op,mailboxBody:body});
        check(r.mailboxResult&&typeof r.mailboxResult==='object','invalid mailbox result');
        return r.mailboxResult;
      })}):undefined;
      const receiptCall=(op,body)=>exclusive(async()=>{
        const r=await call({op:'native-mailbox-lab',mailboxOp:op,mailboxBody:body});
        check(r.mailboxResult&&typeof r.mailboxResult==='object','invalid native receipt result');
        return r.mailboxResult;
      });
      return Object.freeze({
        ...(mailbox?{mailbox,sealReceipt:(item,payload)=>receiptCall('receipt-seal',{id:item.id,digest:item.digest,payload}),openReceipt:record=>receiptCall('receipt-open',record),openDraft:(file,record)=>receiptCall('draft-open',{file,record})}:{}),
        publicKeys:Object.freeze({signing:Object.freeze(signing.jwk),encryption:Object.freeze(enc.jwk)}),
        // Enrollment is a separate, one-time locally approved native broker
        // operation; it does NOT install a live account or revoke old keys.
        async signEnrollment(challenge){return exclusive(()=>signNativeEnrollment(challenge));},
        async openHybrid(record,{recover=false}={}){return exclusive(async()=>{
          const c=record?.context;
          check(c?.to===pqMode.address&&c.toDeviceId===pqMode.deviceId,'wrong recipient');
          verified(record,await peers(c));
          const r=await call({op:'mail-open-hybrid-lab',pqContext:c,pqEnvelope:record.envelope,senderAuth:record.senderAuth,...(recover===true?{recover:true}:{})});
          const plain=b64(r.message,1,8192);
          try{verified(record,await peers(c));return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(plain));}finally{plain.fill(0);}
        });},
        async sealHybrid(context,payload,{recover=false}={}){return exclusive(async()=>{
          check(context?.from===pqMode.address&&context.fromDeviceId===pqMode.deviceId,'wrong sender');
          const raw=Buffer.from(JSON.stringify(payload));check(raw.length>=1&&raw.length<=8192,'invalid message size');
          try{
            await peers(context);
            const r=await call({op:'mail-seal-hybrid-lab',pqContext:context,message:raw.toString('base64url'),...(recover===true?{recover:true}:{})});
            const record={format:'quantic-native-mail',version:1,context,envelope:r.pqEnvelope,senderAuth:r.senderAuth};
            verified(record,await peers(context));return record;
          }finally{raw.fill(0);}
        });},
        close(){
          // Close stdin after queued operations so the broker can exit normally
          // and run its cleanup; a stuck process is forcibly terminated.
          if(closed)return;
          if(busy||waiter){fail();return;}
          closed=true;child.stdin.end();
          const timer=setTimeout(()=>child.kill(),2000);timer.unref();
          child.once('exit',()=>clearTimeout(timer));
        }
      });
    }
    return Object.freeze({
      publicKeys:Object.freeze({signing:Object.freeze(signing.jwk),encryption:Object.freeze(enc.jwk)}),
      async openStatic(envelope){
        const r=await call({op:'mail-open-static-lab',mail:normalizeClassicalEnvelope(envelope)});
        try{return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(b64(r.message,1,8192)));}
        catch{fail();throw Error('invalid native plaintext');}
      },
      signEnrollment:signNativeEnrollment,
      close(){fail();}
    });
  }catch(error){fail();throw error;}
}
