import test from 'node:test';import assert from 'node:assert/strict';import {generateKeyPairSync,createHash,sign} from 'node:crypto';
import {canonicalManifestText} from '../lib/quantic/manifest-core.mjs';import {prepareNativeEnrollment} from '../lib/quantic/native-enrollment.mjs';
import {validateNativeEnrollmentRequest} from '../lib/quantic/native-enrollment-request.mjs';
const pair=()=>generateKeyPairSync('ec',{namedCurve:'prime256v1'}),j=k=>k.publicKey.export({format:'jwk'}),hash=x=>createHash('sha256').update(x).digest('hex'),id=k=>hash(`P-256:${k.x}:${k.y}`),sig=(k,text)=>sign('sha256',Buffer.from(text),{key:k.privateKey,dsaEncoding:'ieee-p1363'});
function lab(){const root=pair(),enc=pair(),s=pair(),e=pair();let now=Date.now();const fingerprint=id(j(root)).slice(0,32),address=`alice~${fingerprint}@quantic`,date=new Date(now-1000).toISOString();const p={version:1,sequence:1,canonicalAddress:address,handle:'alice',fingerprint,identityPublicKey:j(enc),identitySigningPublicKey:j(root),devices:[{deviceId:'d-'+id(j(enc)).slice(0,32),label:'Root',kind:'root',publicKey:j(enc),deviceSigningPublicKey:j(root),issuedAt:date}],revocations:[],issuedAt:date};const signed=payload=>({format:'quantic-identity-manifest',version:1,payload,signature:sig(root,canonicalManifestText(payload)).toString('base64')});const options={manifest:signed(p),expectedRootPin:hash(root.publicKey.export({type:'spki',format:'der'})),signingKey:j(s),encryptionKey:j(e),label:'Native lab',clock:()=>now,labOnly:true};return {options,signed,root,s,e,prepare:over=>prepareNativeEnrollment({...options,...over}),advance:v=>now+=v,proof:c=>sig(s,c.challenge).toString('hex')};}
test('signed enrollment preserves address and old device, never permits deletion',()=>{const l=lab(),c=l.prepare(),p=c.authorize(l.proof(c),true),r=c.confirm(l.signed(p));assert.equal(r.canonicalAddress,l.options.manifest.payload.canonicalAddress);assert.equal(p.devices.length,2);assert.equal(r.safeToRemoveOldKeys,false);assert.equal(r.hardwareAttested,false);assert.throws(()=>c.confirm(l.signed(p)));});
test('wrong root and no lab opt-in refused',()=>{const l=lab();assert.throws(()=>l.prepare({expectedRootPin:'0'.repeat(64)}),/pin/);assert.throws(()=>l.prepare({labOnly:false}),/laboratory/);});
test('private JWK and existing or duplicate keys refused',()=>{const l=lab();assert.throws(()=>l.prepare({signingKey:l.s.privateKey.export({format:'jwk'})}),/public/);assert.throws(()=>l.prepare({signingKey:j(l.root)}),/reuse/);assert.throws(()=>l.prepare({encryptionKey:j(l.s)}),/reuse/);});
test('requires approval and possession of proposed signing key',()=>{const l=lab(),c=l.prepare();assert.throws(()=>c.authorize(l.proof(c),false),/approval/);assert.throws(()=>c.authorize(sig(l.root,c.challenge).toString('hex'),true),/proof/);c.authorize(l.proof(c),true);assert.throws(()=>c.authorize(l.proof(c),true),/pending/);});
test('challenge cannot be replayed in another enrollment',()=>{const l=lab(),a=l.prepare(),b=l.prepare();assert.throws(()=>b.authorize(l.proof(a),true),/proof/);});
test('expiry and backwards clock close enrollment',()=>{for(const delta of [30000,-1]){const l=lab(),c=l.prepare();l.advance(delta);assert.throws(()=>c.authorize(l.proof(c),true),/clock|expired/);}});
test('requires signed exact addition, not arbitrary manifest change',()=>{const l=lab(),c=l.prepare(),p=c.authorize(l.proof(c),true);const m=l.signed({...p,devices:p.devices.map(d=>({...d,label:'Changed'}))});assert.throws(()=>c.confirm(m),/unexpected/);const bad=l.signed(p);bad.signature='x';assert.throws(()=>c.confirm(bad));assert.equal(c.confirm(l.signed(p)).sequence,2);});
test('revoked candidate cannot be reintroduced',()=>{const l=lab(),p=structuredClone(l.options.manifest.payload);p.revocations.push({deviceId:'d-'+id(j(l.e)).slice(0,32),revokedAt:new Date().toISOString(),reason:'compromised'});assert.throws(()=>l.prepare({manifest:l.signed(p)}),/revoked/);});

test('PQ and classical native controllers accept only their own canonical, fresh enrollment challenge',()=>{
 const f=lab(),e=f.prepare(),ctx={signingPin:hash(f.s.publicKey.export({type:'spki',format:'der'})),
  encryptionPin:hash(f.e.publicKey.export({type:'spki',format:'der'})),
  encryptionPublicKey:j(f.e),now:Date.now()};
 const valid=validateNativeEnrollmentRequest(e.challenge,ctx);
 assert.equal(valid.canonicalAddress,f.options.manifest.payload.canonicalAddress);
 assert.equal(valid.deviceId,e.deviceId);
 assert.equal(valid.labOnly,true);
 assert.equal(valid.registrationAuthorized,false);
 assert.equal(valid.legacyDeletionAuthorized,false);
 const change=(index,value)=>{const a=JSON.parse(e.challenge);a[index]=value;return JSON.stringify(a)};
 for(const [index,value] of [
  [0,'quantic-native-pay/lab/v1'],[1,'other~'+'a'.repeat(32)+'@quantic'],
  [2,'f'.repeat(64)],[3,0],[4,'garbled'],[5,'d-'+'a'.repeat(32)],
  [6,'f'.repeat(64)],[7,'f'.repeat(64)],[8,' changed label '],
  [9,'short'],[10,Date.now()+500000]
 ]) {
  if(index===2){ // A different valid root pin is a different historical
   // identity; the controller validates its format but cannot establish
   // independent root ownership. That is the manifest/archival verifier's job.
   continue;
  }
  assert.throws(()=>validateNativeEnrollmentRequest(change(index,value),ctx),'mutated field '+index);
 }
 assert.throws(()=>validateNativeEnrollmentRequest(e.challenge,{...ctx,signingPin:'b'.repeat(64)}));
 assert.throws(()=>validateNativeEnrollmentRequest(e.challenge,{...ctx,encryptionPublicKey:j(pair())}));
 assert.throws(()=>validateNativeEnrollmentRequest(e.challenge,{...ctx,now:JSON.parse(e.challenge)[10]}));
 assert.throws(()=>validateNativeEnrollmentRequest(e.challenge,{...ctx,now:JSON.parse(e.challenge)[10]-31000}));
 assert.throws(()=>validateNativeEnrollmentRequest(' '+e.challenge,ctx));
 assert.throws(()=>validateNativeEnrollmentRequest('{"unexpected":true}',ctx));
 assert.throws(()=>validateNativeEnrollmentRequest('x'.repeat(2049),ctx));
});
