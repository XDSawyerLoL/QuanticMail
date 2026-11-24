// Strict synthetic Windows PQ two-party provisioning assistant.
// This wraps the EXISTING native Windows key generator. It cannot mint an
// independent quorum, authority attestation, contact certificate or relay.
// Never use real user identities and never claim remote enrollment.
import {createHash,createPublicKey} from 'node:crypto';
import {spawn} from 'node:child_process';
import {access,stat,readFile} from 'node:fs/promises';
import {win32} from 'node:path';
import {deviceIdForPublicKeyNode} from '../lib/quantic/manifest-node.mjs';

const refuse=x=>{if(!x)throw Error('Two-party Windows PQ provision laboratory refused');};
const hex=/^[0-9a-f]{64}$/;
const address=/^[a-z0-9][a-z0-9._-]{2,31}~[a-f0-9]{32}@quantic$/;
const b64=(s,n)=>{
 refuse(typeof s==='string'&&s.length<=Math.ceil(n/3)*4+4);
 const raw=Buffer.from(s,'base64url');
 refuse(raw.length===n&&raw.toString('base64url')===s);
 return raw;
};
const sha=b=>createHash('sha256').update(b).digest('hex');
function validatePublicProvision(raw,expectedAddress){
 refuse(raw&&typeof raw==='object'&&!Array.isArray(raw)&&raw.status==='local-provision-only-not-enrolled'
  &&raw.backend==='windows-software-pq-storage-lab'&&raw.address===expectedAddress
  &&typeof raw.deviceId==='string'&&/^d-[a-f0-9]{32}$/.test(raw.deviceId)
  &&[raw.signingPin,raw.encryptionPin,raw.kemPin,raw.dsaPin].every(x=>hex.test(x)));
 const signing=b64(raw.signing,65),encryption=b64(raw.encryption,65);
 function ecPoint(point){
  refuse(point[0]===4);
  const jwk={kty:'EC',crv:'P-256',x:point.subarray(1,33).toString('base64url'),y:point.subarray(33).toString('base64url')};
  const key=createPublicKey({key:jwk,format:'jwk'});
  refuse(key.asymmetricKeyDetails?.namedCurve==='prime256v1');
  return {jwk,pin:sha(key.export({format:'der',type:'spki'}))};
 }
 const s=ecPoint(signing),e=ecPoint(encryption);
 refuse(s.pin===raw.signingPin&&e.pin===raw.encryptionPin
  &&deviceIdForPublicKeyNode(e.jwk,32)===raw.deviceId);
 for(const [encoded,n,pin,kind] of [
  [raw.kemPublic,1206,raw.kemPin,'ml-kem-768'],
  [raw.dsaPublic,1974,raw.dsaPin,'ml-dsa-65']
 ]){
  const spki=b64(encoded,n);
  const publicKey=createPublicKey({key:spki,format:'der',type:'spki'});
  refuse(publicKey.asymmetricKeyType===kind
   &&publicKey.export({format:'der',type:'spki'}).equals(spki)
   &&sha(spki)===pin);
 }
 b64(raw.controllerPublic,32);
 // Only public pins and device identifiers are needed for handoff.
 return Object.freeze({address:expectedAddress,deviceId:raw.deviceId,
  signingPin:raw.signingPin,encryptionPin:raw.encryptionPin,
  kemPin:raw.kemPin,dsaPin:raw.dsaPin,controllerPublic:raw.controllerPublic,
  publicKeys:Object.freeze({
   signingP256:Object.freeze(s.jwk),encryptionP256:Object.freeze(e.jwk),
   kemSpkiBase64url:raw.kemPublic,dsaSpkiBase64url:raw.dsaPublic
  }),
  nativeProvisioned:true,remotelyEnrolled:false});
}
export function twoPartyWindowsPlan({root,binary,binarySha256,first,second}){
 refuse(typeof root==='string'&&win32.isAbsolute(root)
  &&/^[A-Za-z]:\\/.test(root)&&win32.normalize(root)===root
  &&root.length>5&&!root.endsWith('\\')&&!root.includes('~')
  &&typeof binary==='string'&&win32.isAbsolute(binary)
  &&/^[A-Za-z]:\\/.test(binary)&&hex.test(binarySha256));
 refuse(first&&second&&address.test(first.address)&&address.test(second.address)
  &&hex.test(first.quorumPin)&&hex.test(second.quorumPin)
  &&first.address!==second.address);
 const one=win32.join(root,'participant-a'),two=win32.join(root,'participant-b');
 refuse(one!==two&&win32.dirname(one)===root&&win32.dirname(two)===root);
 return Object.freeze({binary,binarySha256,root,
  participants:Object.freeze([
   Object.freeze({dir:one,address:first.address,quorumPin:first.quorumPin}),
   Object.freeze({dir:two,address:second.address,quorumPin:second.quorumPin})
  ])});
}
async function notExists(path){
 try{await access(path);throw Error('Existing participant directory may never be overwritten');}
 catch(e){if(e?.code!=='ENOENT')throw e;}
}
export async function checkTwoPartyWindowsPlan(plan,{read=readFile,inspect=stat,missing=notExists}={}){
 const root=await inspect(plan.root);
 refuse(root.isDirectory());
 const executable=await inspect(plan.binary);
 refuse(executable.isFile()&&executable.size>0&&executable.size<256*1024*1024);
 refuse(sha(await read(plan.binary))===plan.binarySha256);
 for(const p of plan.participants)await missing(p.dir);
 return true;
}
export function nativeWindowsProvisionChild(binary,dir,quorumPin,address){
 return new Promise((resolve,reject)=>{
  // The Go broker collects TWO distinct passwords and approval from the
  // local console; JS does not read, log, cache or pass either password.
  const child=spawn(binary,['--provision-windows-controller-lab',dir,quorumPin,address],{
   shell:false,windowsHide:false,stdio:['inherit','pipe','inherit']
  });
  let stdout='',finished=false;
  const finish=(error,result)=>{if(finished)return;finished=true;error?reject(error):resolve(result);};
  child.stdout.on('data',chunk=>{
   stdout+=chunk.toString('utf8');
   if(Buffer.byteLength(stdout)>16384){child.kill();finish(Error('Unbounded native provision result'));}
  });
  child.once('error',()=>finish(Error('Native Windows provision failed')));
  child.once('exit',code=>{
   if(code!==0){finish(Error('Native Windows provision refused; keep any partial directory'));return;}
   try{finish(null,JSON.parse(stdout));}
   catch{finish(Error('Unrecognized native public result; keep partial directory'));}
  });
 });
}
export async function provisionTwoWindowsLab(plan,{
 check=checkTwoPartyWindowsPlan,
 invoke=nativeWindowsProvisionChild,
 afterEach=async()=>{}
}={}){
 await check(plan);
 const results=[];
 for(const p of plan.participants){
  // Never start participant B if participant A was not verified.
  const raw=await invoke(plan.binary,p.dir,p.quorumPin,p.address);
  const result=validatePublicProvision(raw,p.address);
  results.push(result);
  await afterEach(results.length,result);
 }
 refuse(results[0].deviceId!==results[1].deviceId
  &&results[0].signingPin!==results[1].signingPin
  &&results[0].kemPin!==results[1].kemPin);
 return Object.freeze({status:'two-local-synthetic-vaults-provisioned',labOnly:true,
  participants:results,remoteAuthoritiesConfigured:false,
  nativeMailRelayConfigured:false,liveAccountEnrollmentAuthorized:false,
  legacyDeletionAuthorized:false});
}


// One local Windows GUI identity. The independent address/quorum pin must
// already have been assigned by the laboratory operator. No enrollment.
export async function provisionSingleWindowsGUI({binary,binarySha256,dir,address:addr,quorumPin},{
 read=readFile,inspect=stat,missing=notExists,
 invoke=nativeWindowsProvisionGUI
}={}){
 refuse(typeof dir==='string'&&win32.isAbsolute(dir)&&/^[A-Za-z]:\\/.test(dir)
  &&win32.normalize(dir)===dir&&dir.length>5&&dir.length<=160&&!dir.includes('~')
  &&typeof binary==='string'&&win32.isAbsolute(binary)&&hex.test(binarySha256)
  &&address.test(addr)&&hex.test(quorumPin)&&!/^0+$/.test(quorumPin));
 const parent=await inspect(win32.dirname(dir));refuse(parent.isDirectory());
 const exe=await inspect(binary);refuse(exe.isFile()&&exe.size>0&&exe.size<256*1024*1024);
 refuse(sha(await read(binary))===binarySha256);
 await missing(dir);
 const raw=await invoke(binary,dir,quorumPin,addr);
 const publicRecord=validatePublicProvision(raw,addr);
 refuse(raw.quorumPin===quorumPin);
 return Object.freeze({status:'local-vault-created-not-enrolled',labOnly:true,
  identity:publicRecord,quorumPin,remoteAuthoritiesConfigured:false,
  nativeMailRelayConfigured:false,liveAccountEnrollmentAuthorized:false});
}
export function nativeWindowsProvisionGUI(binary,dir,quorumPin,addr){
 const system=process.env.SystemRoot??process.env.SYSTEMROOT;
 refuse(process.platform==='win32'&&typeof system==='string'&&win32.isAbsolute(system));
 return new Promise((resolve,reject)=>{
  const child=spawn(binary,['--provision-windows-controller-gui-lab',dir,quorumPin,addr],{
   shell:false,windowsHide:true,cwd:win32.dirname(binary),stdio:['ignore','pipe','ignore'],
   env:{SystemRoot:system,WINDIR:system,PATH:win32.dirname(binary)+';'+win32.join(system,'System32')}
  });
  let done=false,size=0;const chunks=[];
  const finish=(err,value)=>{if(done)return;done=true;clearTimeout(timer);if(err)child.kill();for(const c of chunks)c.fill(0);err?reject(err):resolve(value);};
  const timer=setTimeout(()=>finish(Error('Native provisioning timed out; preserve any partial vault')),300000);
  child.on('error',()=>finish(Error('Native provisioning unavailable')));
  child.stdout.on('error',()=>finish(Error('Native provisioning output unavailable')));
  child.stdout.on('data',c=>{size+=c.length;if(size>16384){finish(Error('Invalid provisioning output'));return;}chunks.push(c);});
  child.on('close',code=>{
   if(code!==0){finish(Error('Native provisioning cancelled or refused; preserve any partial vault'));return;}
   try{finish(null,JSON.parse(Buffer.concat(chunks).toString('utf8')));}catch(e){finish(e);}
  });
 });
}
