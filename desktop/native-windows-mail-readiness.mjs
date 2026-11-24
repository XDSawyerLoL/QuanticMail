// Read-only, fail-closed bridge between the separately pinned Windows PQ
// identity, four mTLS authorities, and an explicitly provisioned Scattering
// carrier. This is not enrollment, a key import, or remote delivery proof.
import {createHash,createPublicKey} from 'node:crypto';
import {readFile,lstat} from 'node:fs/promises';
import {win32} from 'node:path';
import {createWindowsNativeStorage} from './native-windows-storage.mjs';
import {windowsScatteringScope} from './native-windows-mail-flow.mjs';
import {bindWindowsDesktopConfig} from './native-windows-desktop.mjs';
import {createAttestedPeerSource} from './native-attested-peer.mjs';

const fail=()=>{throw Error('Windows two-host mail readiness refused');};
const check=x=>{if(!x)fail();};
const sha=b=>createHash('sha256').update(b).digest('hex');
const hex=/^[0-9a-f]{64}$/;
const addr=/^[a-z0-9][a-z0-9._-]{2,31}~[a-f0-9]{32}@quantic$/;
const dev=/^d-[a-f0-9]{32}$/;
const pinnedPaths=/^peer-[a-z0-9-]{1,48}\.pem$/;
const keys=(obj,names)=>check(obj&&Object.getPrototypeOf(obj)===Object.prototype
 &&Object.keys(obj).length===names.length&&names.every(k=>Object.hasOwn(obj,k)));
const strictPath=(p)=>check(typeof p==='string'&&win32.isAbsolute(p)&&/^[A-Za-z]:\\/.test(p)
 &&win32.normalize(p)===p&&!p.includes('~')&&p.length<=240);
function parseKey(encoded,encoding,kind,bytes){
 check(typeof encoded==='string'&&encoded.length<=Math.ceil(bytes*4/3)+5);
 const raw=Buffer.from(encoded,encoding);
 check(raw.length===bytes&&raw.toString(encoding)===encoded);
 const pub=createPublicKey({key:raw,type:'spki',format:'der'});
 check(pub.asymmetricKeyType===kind&&pub.export({type:'spki',format:'der'}).equals(raw));
 return sha(raw);
}
const contactFields=['classicalSigningPin','classicalEncryptionPin','mlKemPin','mlDsaPin'];
function validTrust(trust){
 keys(trust,['format','labOnly','self','peer','authorities','carrierRole']);
 check(trust.format==='quantic-two-host-trust-lab/v1'&&trust.labOnly===true);
 const who=['address','deviceId','rootPin','pqRootPin',...contactFields];
 for(const w of [trust.self,trust.peer]){
  keys(w,who);check(addr.test(w.address)&&dev.test(w.deviceId));
  check(who.slice(2).every(k=>hex.test(w[k])));
 }
 check(trust.self.address!==trust.peer.address&&trust.self.deviceId!==trust.peer.deviceId);
 check(Array.isArray(trust.authorities)&&trust.authorities.length===4);
 const unique=new Set(),tls=new Set();
 for(const a of trust.authorities){
  keys(a,['pin','tlsPin']);
  check(hex.test(a.pin)&&hex.test(a.tlsPin)&&!unique.has(a.pin)&&!tls.has(a.tlsPin));
  unique.add(a.pin);tls.add(a.tlsPin);
 }
 check(trust.carrierRole==='client'||trust.carrierRole==='relay');
 return trust;
}
function contactPins(c){
 const fields=[['classicalSigningSpki','ec',91],
 ['classicalEncryptionSpki','ec',91],
 ['mlKemEncryptionSpki','ml-kem-768',1206],
 ['mlDsaSigningSpki','ml-dsa-65',1974]];
 const result={};
 const mapped=['classicalSigningPin','classicalEncryptionPin','mlKemPin','mlDsaPin'];
 for(let i=0;i<fields.length;i++) {
  const [field,kind,size]=fields[i];
  const bytes=Buffer.from(c[field],'base64');
  check(typeof c[field]==='string'&&bytes.toString('base64')===c[field]&&bytes.length===size);
  const key=createPublicKey({key:bytes,type:'spki',format:'der'});
  check((kind==='ec'?key.asymmetricKeyType==='ec'&&key.asymmetricKeyDetails?.namedCurve==='prime256v1':key.asymmetricKeyType===kind)
   &&key.export({type:'spki',format:'der'}).equals(bytes));
  result[mapped[i]]=sha(bytes);
 }
 return result;
}
const sameContact=(a,b)=>a.address===b.address&&a.deviceId===b.deviceId
 &&contactFields.every(k=>contactPins(a)[k]===contactPins(b)[k]);
export function verifyWindowsTwoHostReadiness(config,contacts,carrier,trust,{now=Date.now(),carrierDir}={}){
 validTrust(trust);
 const p=config?.pqMode,win=config?.windowsLab;
 check(config?.labOnly===true&&win?.enabled===true&&p?.enabled===true&&config.nativeRelay===undefined);
 strictPath(win.dir);strictPath(carrierDir);
 check(win.dir!==carrierDir&&p.address===trust.self.address&&p.deviceId===trust.self.deviceId
  &&p.rootPin===trust.self.pqRootPin);
 // Signed identity ownership remains separate from current device:
 // the offline preflight cannot prove a historical owner.
 check(config.signingPin===trust.self.classicalSigningPin
  &&config.encryptionPin===trust.self.classicalEncryptionPin
  &&p.kemPin===trust.self.mlKemPin&&p.dsaPin===trust.self.mlDsaPin);
 const scoped=windowsScatteringScope(config);
 check(scoped.credentialMode==='vault-sealed-v1'?scoped.token===undefined:typeof scoped.token==='string'&&/^[A-Za-z0-9._~-]{40,256}$/.test(scoped.token));
 const source=p.authority;
 keys(source,['authorities','caFile','clientCertFile','clientKeyFile']);
 check(source.authorities.length===4);
 const allowedPath=path=>{strictPath(path);
  check(win32.dirname(path)===win.dir&&pinnedPaths.test(win32.basename(path)));
 };
 for(const file of [source.caFile,source.clientCertFile,source.clientKeyFile])allowedPath(file);
 check(new Set([source.caFile,source.clientCertFile,source.clientKeyFile]).size===3);
 const expected=new Map(trust.authorities.map(x=>[x.pin,x.tlsPin])),observed=new Set(),origins=new Set();
 for(const a of source.authorities){
  keys(a,['url','pin','publicKey','tlsPin']);
  check(hex.test(a.pin)&&hex.test(a.tlsPin)&&expected.get(a.pin)===a.tlsPin
   &&!observed.has(a.pin));
  const url=new URL(a.url);
  check(url.protocol==='https:'&&url.pathname==='/native-checkpoint'
   &&url.username===''&&url.password===''&&url.search===''&&url.hash===''
   &&!origins.has(url.origin));
  check(parseKey(a.publicKey,'base64url','ed25519',44)===a.pin);
  observed.add(a.pin);origins.add(url.origin);
 }
 check(observed.size===4&&expected.size===4);
 check(Array.isArray(contacts)&&contacts.length===1);
 const peer=contacts[0];
 check(peer?.address===trust.peer.address&&peer?.deviceId===trust.peer.deviceId
  &&Number.isSafeInteger(peer.expires)&&peer.expires>now);
 const pins=contactPins(peer);
 check(contactFields.every(k=>pins[k]===trust.peer[k]));
 keys(carrier,['labOnly','role','secretHex','epochHex','recvPort','httpPort','queueDir','stateDir']);
 check(carrier.labOnly===true&&carrier.role===trust.carrierRole
  &&hex.test(carrier.secretHex)&&hex.test(carrier.epochHex)
  &&carrier.secretHex!==carrier.epochHex
  &&Number.isInteger(carrier.recvPort)&&carrier.recvPort>=1&&carrier.recvPort<=65535
  &&Number.isInteger(carrier.httpPort)&&carrier.httpPort>=1&&carrier.httpPort<=65535
  &&carrier.queueDir===win32.join(carrierDir,'queue')
  &&carrier.stateDir===win32.join(carrierDir,'state'));
 if(carrier.role==='client')check(Number(new URL(scoped.endpoint).port)===carrier.httpPort);
 return Object.freeze({status:'offline-public-anchors-verified',labOnly:true,
  self:trust.self.address,peer:trust.peer.address,authorityCount:4,
  contactPinsVerified:true,carrierRole:carrier.role,
  authorityQuorumVerified:false,remoteTransportVerified:false,
  liveAccountEnrollmentAuthorized:false,legacyDeletionAuthorized:false});
}
async function privateJson(storage,path){
 const bytes=await storage.read(path);
 try{
  check(Buffer.isBuffer(bytes)&&bytes.length>1&&bytes.length<=131072);
  return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));
 }finally{bytes.fill(0);}
}
export async function runWindowsTwoHostReadiness({binary,binarySha256,dir,carrierDir,trustFile,trustSha256,live=false},{
 readTrust=readFile,inspect=lstat,storageFactory=createWindowsNativeStorage,
 peerSourceFactory=createAttestedPeerSource,now=()=>Date.now()
}={}){
 check(hex.test(binarySha256)&&hex.test(trustSha256)&&typeof live==='boolean');
 for(const p of [binary,dir,carrierDir,trustFile])strictPath(p);
 check(dir!==carrierDir&&win32.extname(trustFile)==='.json');
 const stat=await inspect(trustFile);
 check(stat.isFile()&&!stat.isSymbolicLink()&&stat.size>1&&stat.size<=16384);
 const raw=await readTrust(trustFile);
 check(Buffer.isBuffer(raw)&&raw.length===stat.size&&sha(raw)===trustSha256);
 const trust=validTrust(JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(raw)));
 const storage=await storageFactory({binary,binarySha256,dir});
 const carrierStorage=await storageFactory({binary,binarySha256,dir:carrierDir});
 const cfg=await privateJson(storage,win32.join(dir,'desktop.json'));
 bindWindowsDesktopConfig(cfg,{binary,binarySha256,dir});
 const contacts=await privateJson(storage,win32.join(dir,'contacts.json'));
 const carrier=await privateJson(carrierStorage,win32.join(carrierDir,'scattering.json'));
 const result=verifyWindowsTwoHostReadiness(cfg,contacts,carrier,trust,{now:now(),carrierDir});
 if(!live)return result;
 const source=await peerSourceFactory(cfg.pqMode.authority,{read:storage.read});
 const self=await source(trust.self.address,trust.self.deviceId);
 const remote=await source(trust.peer.address,trust.peer.deviceId);
 check(self?.contact?.address===trust.self.address&&self.contact.deviceId===trust.self.deviceId
  &&remote?.contact&&sameContact(remote.contact,contacts[0])
  &&self.checkpoint.rootPin===trust.self.rootPin
  &&self.checkpoint.pqRootPin===trust.self.pqRootPin
  &&remote.checkpoint.rootPin===trust.peer.rootPin
  &&remote.checkpoint.pqRootPin===trust.peer.pqRootPin
  &&contactFields.every(k=>contactPins(self.contact)[k]===trust.self[k])
  &&contactFields.every(k=>contactPins(remote.contact)[k]===trust.peer[k]));
 return Object.freeze({...result,status:'fresh-mtls-3-of-4-quorum-and-contact-verified',
  authorityQuorumVerified:true,remoteTransportVerified:false});
}
