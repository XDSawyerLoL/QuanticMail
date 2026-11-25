// Local-only native identity assistant. All private operations use the new
// domain-separated Go vault. Node never receives either vault password.
import {spawn} from 'node:child_process';
import {createHash,createPublicKey,randomUUID} from 'node:crypto';
import {readFile,readdir} from 'node:fs/promises';
import {win32} from 'node:path';
import {createWindowsNativeStorage} from './native-windows-storage.mjs';
import {saveWindowsDraft} from './native-windows-draft.mjs';
import {normalizeNativeRecord,nativeRecordDigest} from '../lib/quantic/native-mailbox.mjs';
import {safeMailDisplay} from './native-vault-desktop.mjs';
import {deviceIdForPublicKeyNode} from '../lib/quantic/manifest-node.mjs';
const check=x=>{if(!x)throw Error('Direct local vault refused');};
const hex=/^[a-f0-9]{64}$/;
const addr=/^[a-z0-9][a-z0-9._-]{2,31}~[a-f0-9]{32}@quantic$/;
const dev=/^d-[a-f0-9]{32}$/;
const sha=b=>createHash('sha256').update(b).digest('hex');
const exact=(o,ks)=>o&&Object.getPrototypeOf(o)===Object.prototype&&Object.keys(o).length===ks.length&&ks.every(k=>Object.hasOwn(o,k));
const parse=b=>JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(b));
async function readJSON(s,p){const raw=await s.read(p);try{return parse(raw);}finally{raw.fill(0);}}
export function verifyLocalDirectIdentity(id,protectedMode=false){
 check(exact(id,['format','address','deviceId','signingPin','encryptionPin','kemPin','dsaPin','signing','encryption','kemPublic','dsaPublic','controllerPublic','localPin'])&&id.format===(protectedMode?'quantic-protected-direct-identity/v1':'quantic-local-direct-identity/v1')&&addr.test(id.address)&&dev.test(id.deviceId));
 check([id.signingPin,id.encryptionPin,id.kemPin,id.dsaPin,id.localPin].every(p=>hex.test(p)&&!/^0+$/.test(p)));
 function decode(s,n){check(typeof s==='string'&&s.length<=Math.ceil(n/3)*4);const b=Buffer.from(s,'base64url');check(b.length===n&&b.toString('base64url')===s);return b;}
 function ec(s,p){
  const b=decode(s,65);check(b[0]===4);
  const jwk={kty:'EC',crv:'P-256',x:b.subarray(1,33).toString('base64url'),y:b.subarray(33).toString('base64url')};
  const k=createPublicKey({key:jwk,format:'jwk'}),der=k.export({type:'spki',format:'der'});
  check(k.asymmetricKeyDetails?.namedCurve==='prime256v1'&&sha(der)===p);return {jwk,der};
 }
 const a=ec(id.signing,id.signingPin),b=ec(id.encryption,id.encryptionPin);
 check(deviceIdForPublicKeyNode(b.jwk,32)===id.deviceId);
 function pq(s,p,n,kind){const raw=decode(s,n),k=createPublicKey({key:raw,type:'spki',format:'der'});check(k.asymmetricKeyType===kind&&k.export({type:'spki',format:'der'}).equals(raw)&&sha(raw)===p);return raw;}
 decode(id.controllerPublic,32);
 return {address:id.address,deviceId:id.deviceId,classicalSigningSpki:a.der.toString('base64'),classicalEncryptionSpki:b.der.toString('base64'),mlKemEncryptionSpki:pq(id.kemPublic,id.kemPin,1206,'ml-kem-768').toString('base64'),mlDsaSigningSpki:pq(id.dsaPublic,id.dsaPin,1974,'ml-dsa-65').toString('base64')};
}
async function invoke(boot,args,input,{spawnProcess=spawn,timeout=300000}={}){
 check(process.platform==='win32'&&win32.isAbsolute(boot.binary)&&win32.isAbsolute(boot.dir)&&hex.test(boot.binarySha256)&&sha(await readFile(boot.binary))===boot.binarySha256);
 const system=process.env.SystemRoot??process.env.SYSTEMROOT;check(win32.isAbsolute(system));
 return new Promise((resolve,reject)=>{
  const child=spawnProcess(boot.binary,args,{shell:false,windowsHide:true,cwd:win32.dirname(boot.binary),env:{SystemRoot:system,WINDIR:system,PATH:win32.dirname(boot.binary)+';'+win32.join(system,'System32')},stdio:['pipe','pipe','ignore']});
  const chunks=[];let size=0,done=false;
  const finish=(e,v)=>{if(done)return;done=true;clearTimeout(timer);if(e)child.kill();for(const c of chunks)c.fill(0);e?reject(e):resolve(v);};
  const timer=setTimeout(()=>finish(Error('Native direct operation timed out')),timeout);
  child.on('error',()=>finish(Error('Native direct operation unavailable')));
  child.stdin.on('error',()=>finish(Error('Native direct operation refused')));
  child.stdout.on('error',()=>finish(Error('Native direct operation refused')));
  child.stdout.on('data',b=>{size+=b.length;if(size>32768){finish(Error('Native output bound'));return;}chunks.push(b);});
  child.on('close',code=>{if(code!==0){finish(Error('Native direct operation refused'));return;}const raw=Buffer.concat(chunks);try{finish(null,raw.length?parse(raw):null);}catch(e){finish(e);}finally{raw.fill(0);}});
  child.stdin.end(input);
 });
}
export async function localDirectOperation(boot,action,fields,{makeStorage=createWindowsNativeStorage,call=invoke,enumerate=readdir,now=Date.now}={}){
 check(typeof action==='string'&&fields&&Object.getPrototypeOf(fields)===Object.prototype);
 const protectedMode=action.startsWith('protected-');if(protectedMode)action=action.slice(10);
 if(protectedMode&&action==='roster'){
  check(exact(fields,['cards'])&&typeof fields.cards==='string'&&Buffer.byteLength(fields.cards)<=32768);
  const raw=Buffer.from(fields.cards);try{
   const r=await call(boot,['--windows-witness-roster-lab'],raw);
   check(hex.test(r?.rosterPin)&&r.cardsPin===sha(raw));return r;
  }finally{raw.fill(0);}
 }
 if(action==='create'){
  check(exact(fields,protectedMode?['alias','roster']:['alias'])&&/^[a-z0-9][a-z0-9._-]{2,31}$/.test(fields.alias));
  if(protectedMode)check(hex.test(fields.roster)&&!/^0+$/.test(fields.roster));
  const id=await call(boot,[protectedMode?'--provision-windows-protected-direct-gui-lab':'--provision-windows-direct-gui-lab',boot.dir,fields.alias,...(protectedMode?[fields.roster]:[])]);
  const contact=verifyLocalDirectIdentity(id,protectedMode);
  if(protectedMode)check(id.localPin===fields.roster);
  return {status:'direct-created',address:contact.address,deviceId:contact.deviceId};
 }
 const s=await makeStorage(boot);
 const id=await readJSON(s,win32.join(boot.dir,'direct-identity.json')),self=verifyLocalDirectIdentity(id,protectedMode);
 if(action==='card'){
  check(exact(fields,[]));
  const card=JSON.stringify([{...self,expires:now()+23*3600000}]);
  return {status:'direct-public-card',card,sha256:sha(card),address:self.address};
 }
 if(action==='import'){
  check(exact(fields,['card','pin'])&&typeof fields.card==='string'&&Buffer.byteLength(fields.card)<=131072&&hex.test(fields.pin)&&sha(fields.card)===fields.pin);
  const raw=Buffer.from(fields.card,'utf8');try{check(await call(boot,[protectedMode?'--import-windows-protected-contact-gui-lab':'--import-windows-direct-contact-gui-lab',boot.dir,fields.pin],raw)===null);}finally{raw.fill(0);}
  return {status:'direct-contact-imported'};
 }
 if(action==='list'){
  check(exact(fields,[]));
  const names=await enumerate(boot.dir);check(Array.isArray(names)&&names.length<=512);
  const items=names.filter(n=>typeof n==='string'&&/^wire-in-[a-f0-9]{40}\.json$/.test(n)).sort().slice(0,64);
  return {status:'direct-incoming',items};
 }
 const pin=fields.pin;check(hex.test(pin));
 const protectedCall=(op,input)=>call(boot,['--windows-protected-direct-gui-lab',boot.dir,pin,op],input);
 if(protectedMode&&action==='pair'){
  check(exact(fields,['pin','cards'])&&typeof fields.cards==='string'&&Buffer.byteLength(fields.cards)<=32768);
  const raw=Buffer.from(fields.cards);try{
   const caps=await call(boot,['--windows-witness-prepare-gui-lab',boot.dir,pin,sha(raw)],raw);
   check(Array.isArray(caps)&&caps.length===4);
   return {status:'direct-witness-pairing',capsules:caps.map(c=>{const card=JSON.stringify(c);return {card,sha256:sha(card)};})};
  }finally{raw.fill(0);}
 }
 if(protectedMode&&['initialize','status','revoke'].includes(action)){
  check(exact(fields,['pin']));return protectedCall(action);
 }
 const bytes=await s.read(win32.join(boot.dir,'contacts.json'));let contacts;
 try{check(sha(bytes)===pin);contacts=parse(bytes);}finally{bytes.fill(0);}
 check(Array.isArray(contacts)&&contacts.length===1&&(protectedMode||contacts[0].expires>now()));
 const peer=contacts[0];check(addr.test(peer.address)&&dev.test(peer.deviceId)&&peer.address!==self.address);
 if(protectedMode){const state=await protectedCall('status');check(state?.status==='direct-protected-active'&&state.address===peer.address&&state.deviceId===peer.deviceId&&Number.isSafeInteger(state.expires)&&state.expires>now());peer.expires=state.expires;}
 async function native(op,file,recover){const raw=Buffer.from(JSON.stringify({op,file,contactPin:pin,recover}));try{return protectedMode?await protectedCall('mail',raw):await call(boot,['--windows-direct-mail-gui-lab',boot.dir],raw);}finally{raw.fill(0);}}
 if(action==='seal'||action==='recover-seal'){
  const recover=action==='recover-seal';let file;
  if(recover){check(exact(fields,['pin','file'])&&/^draft-[a-f0-9]{32}\.json$/.test(fields.file));file=fields.file;}
  else{
   check(exact(fields,['pin','subject','body']));
   // saveWindowsDraft is local DPAPI persistence; its scope validator requires
   // a loopback URL but it performs no socket operation and uses no token.
   const cfg={windowsLab:{dir:boot.dir},pqMode:{enabled:true,address:self.address,deviceId:self.deviceId},windowsScattering:{enabled:true,address:self.address,deviceId:self.deviceId,endpoint:'http://127.0.0.1:1/',receiptKeyFile:win32.join(boot.dir,'receipt.key')}};
   file=(await saveWindowsDraft(cfg,contacts,s,{to:peer.address,subject:fields.subject,body:fields.body})).file;
  }
  const draft=await readJSON(s,win32.join(boot.dir,file));
  check(draft.context.from===self.address&&draft.context.fromDeviceId===self.deviceId&&draft.context.to===peer.address&&draft.context.toDeviceId===peer.deviceId);
  const result=await native('seal',file,recover);
  check(result?.ok===true&&result.pqEnvelope&&result.senderAuth);
  const record=normalizeNativeRecord({format:'quantic-native-mail',version:1,context:draft.context,envelope:result.pqEnvelope,senderAuth:result.senderAuth});
  const wire=file.replace(/^draft-/,'wire-'),p=win32.join(boot.dir,wire),raw=Buffer.from(JSON.stringify(record)+'\n');
  try{
   try{await s.writeWire(p,raw);}catch{if(!recover)throw Error('Wire write not confirmed');}
   const reread=await s.read(p);try{check(reread.equals(raw));}finally{reread.fill(0);}
  }finally{raw.fill(0);}
  return {status:'direct-wire-prepared',digest:nativeRecordDigest(record),wireFile:wire,noAutomaticRetry:true};
 }
 if(action==='open'||action==='recover-open'){
  check(exact(fields,['pin','file'])&&/^wire-in-[a-f0-9]{40}\.json$/.test(fields.file));
  const result=await native('open',fields.file,action==='recover-open');
  check(result?.ok===true&&typeof result.message==='string');
  const raw=Buffer.from(result.message,'base64url');try{
   check(raw.length>0&&raw.length<=8192&&raw.toString('base64url')===result.message);
   return {status:'direct-message-opened',display:safeMailDisplay(parse(raw))};
  }finally{raw.fill(0);}
 }
 throw Error('Unknown local operation');
}
