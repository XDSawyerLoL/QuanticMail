// Operator-prepared kit; no device private keys and no trust-on-first-use.
import {createHash,createPrivateKey,createPublicKey,X509Certificate} from 'node:crypto';
import {bindNativeContact} from './native-identity-bridge.mjs';
import {verifyNativeEnrollmentReceipts} from './native-enrollment-registry-lab.mjs';
const check=x=>{if(!x)throw Error('Native session kit refused');};
const sha=b=>createHash('sha256').update(b).digest('hex');
const hex=/^[a-f0-9]{64}$/;
const exact=(o,k)=>check(o&&typeof o==='object'&&!Array.isArray(o)&&Object.keys(o).length===k.length&&k.every(n=>Object.hasOwn(o,n)));
export function validateNativeSessionConfiguration(cfg,tls){
 exact(cfg,['format','labOnly','service','authorities','candidate','expected','enrollmentReceipts','clientPin','tlsFiles']);
 check(cfg.format==='quantic-native-session-config-lab/v1'&&cfg.labOnly===true&&hex.test(cfg.clientPin));
 const {candidate,expected,authorities,service}=cfg;
 const p=candidate?.policyCandidate;
 check(candidate?.format==='quantic-native-owner-candidate-lab/v1'&&candidate.labOnly===true&&candidate.registrationAuthorized===false&&p?.active===false);
 const pins=['address','deviceId','rootPin','pqRootPin'];
 check(pins.every(k=>p[k]===expected[k]));
 check(['rootPin','pqRootPin','quorumPin','signingPin','encryptionPin','kemPin','dsaPin'].every(k=>typeof expected[k]==='string'&&hex.test(expected[k])));
 check(typeof expected.controllerPublic==='string'&&/^[A-Za-z0-9_-]{43}$/.test(expected.controllerPublic));
 const now=Date.now(),c=bindNativeContact(candidate.bundle,{...p,expires:now+10000},now);
 for(const [field,pin] of [['classicalSigningSpki','signingPin'],['classicalEncryptionSpki','encryptionPin'],['mlKemEncryptionSpki','kemPin'],['mlDsaSigningSpki','dsaPin']])check(sha(Buffer.from(c[field],'base64'))===expected[pin]);
 const origins=new Set(),tlsPins=new Set(),keys=new Set();
 function endpoint(a){
  check(typeof a.url==='string'&&typeof a.tlsPin==='string'&&hex.test(a.tlsPin));
  const u=new URL(a.url);
  check(u.protocol==='https:'&&u.hostname&&u.pathname==='/'&&!u.username&&!u.password&&!u.search&&!u.hash&&!origins.has(u.origin)&&!tlsPins.has(a.tlsPin));
  origins.add(u.origin);tlsPins.add(a.tlsPin);
 }
 exact(service,['url','tlsPin']);endpoint(service);
 check(Array.isArray(authorities)&&authorities.length===4);
 for(const a of authorities){
  exact(a,['url','tlsPin','pin','publicKey']);endpoint(a);
  const raw=Buffer.from(a.publicKey,'base64url');
  check(raw.length===44&&raw.toString('base64url')===a.publicKey&&sha(raw)===a.pin&&!keys.has(a.pin)&&createPublicKey({key:raw,format:'der',type:'spki'}).asymmetricKeyType==='ed25519');keys.add(a.pin);
 }
 exact(cfg.tlsFiles,['ca','cert','key']);
 check(Object.values(cfg.tlsFiles).every(n=>typeof n==='string'&&/^peer-[a-z0-9-]{1,48}\.pem$/.test(n))&&new Set(Object.values(cfg.tlsFiles)).size===3);
 const cert=new X509Certificate(tls.cert);
 check(sha(cert.raw)===cfg.clientPin&&cert.checkPrivateKey(createPrivateKey(tls.key))&&Date.parse(cert.validFrom)<=now&&now<Date.parse(cert.validTo));
 new X509Certificate(tls.ca);
 verifyNativeEnrollmentReceipts(cfg.enrollmentReceipts,authorities,candidate,expected);
 return cfg;
}
export function createNativeSessionKit({configuration,tls,labOnly}){
 check(labOnly===true);
 const cfg=structuredClone(configuration);
 validateNativeSessionConfiguration(cfg,tls);
 const bytes=Buffer.from(JSON.stringify(cfg));
 const files={'session.json':bytes.toString('base64url')};
 for(const k of ['ca','cert','key']){
  const b=Buffer.from(tls[k]);try{check(b.length>0&&b.length<=32768);files[cfg.tlsFiles[k]]=b.toString('base64url');}finally{b.fill(0);}
 }
 const raw=Buffer.from(JSON.stringify({format:'quantic-windows-session-kit-lab/v1',address:cfg.expected.address,deviceId:cfg.expected.deviceId,files}));
 check(raw.length<=131072);
 return {bytes:raw,kitSha256:sha(raw),configurationSha256:sha(bytes)};
}
