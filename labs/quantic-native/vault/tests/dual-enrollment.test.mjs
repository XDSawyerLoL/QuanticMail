import test from 'node:test';
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {createInterface} from 'node:readline';
import {generateKeyPairSync,createHash,sign,randomBytes} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {canonicalManifestText} from '../lib/quantic/manifest-core.mjs';
import {prepareDualEnrollment} from '../lib/quantic/native-enrollment-dual.mjs';
const hash=s=>createHash('sha256').update(s).digest('hex');
const pair=()=>generateKeyPairSync('ec',{namedCurve:'prime256v1'});
const j=k=>k.publicKey.export({format:'jwk'});
const id=k=>hash(`P-256:${k.x}:${k.y}`).slice(0,32);
function point(raw){const b=Buffer.from(raw,'base64url');assert.equal(b.length,65);return {kty:'EC',crv:'P-256',x:b.subarray(1,33).toString('base64url'),y:b.subarray(33).toString('base64url')}}
function broker(t){const exe=fileURLToPath(new URL(process.platform==='win32'?'../VaultIsolated.exe':'../VaultIsolated-linux',import.meta.url));const child=spawn(exe,['--broker-test-software'],{stdio:['pipe','pipe','inherit']});const lines=createInterface({input:child.stdout})[Symbol.asyncIterator]();t.after(()=>{child.stdin.end();child.kill()});return async(op,fields={})=>{child.stdin.write(JSON.stringify({op,...fields})+'\n');const r=await lines.next();assert.equal(r.done,false);return JSON.parse(r.value)}}
function fixture(){const root=pair(),enc=pair(),fp=id(j(root)),addr=`alice~${fp}@quantic`,date=new Date(Date.now()-1000).toISOString();const payload={version:1,sequence:1,canonicalAddress:addr,handle:'alice',fingerprint:fp,identityPublicKey:j(enc),identitySigningPublicKey:j(root),devices:[{deviceId:'d-'+id(j(enc)),label:'Root',kind:'root',publicKey:j(enc),deviceSigningPublicKey:j(root),issuedAt:date}],revocations:[],issuedAt:date};function signed(p){return {format:'quantic-identity-manifest',version:1,payload:p,signature:sign('sha256',Buffer.from(canonicalManifestText(p)),{key:root.privateKey,dsaEncoding:'ieee-p1363'}).toString('base64')}}return {signed,manifest:signed(payload),expectedRootPin:hash(root.publicKey.export({format:'der',type:'spki'}))}}
async function setup(t){const a=broker(t),b=broker(t),pb=await b('public'),f=fixture();let now=Date.now();const c=()=>prepareDualEnrollment({...f,signingKey:point(pb.signing),encryptionKey:point(pb.encryption),label:'Native lab',labOnly:true,clock:()=>now});return {a,b,f,c,advance:delta=>now+=delta};}
async function proofs(b,c){const r=await b('open',{packet:c.packet});assert.equal(r.ok,true);const s=await b('enroll-proof',{enrollment:c.challenge,approved:true});assert.equal(s.ok,true);return [s.enrollmentProof,r.message];}
test('dual enrollment succeeds with two real subprocess key operations',async t=>{const x=await setup(t),c=x.c();assert.equal((await x.a('open',{packet:c.packet})).ok,false);const [s,r]=await proofs(x.b,c);const p=c.authorize(s,r,true);assert.equal(c.confirm(x.f.signed(p)).safeToRemoveOldKeys,false);assert.equal(p.devices.length,2);});
test('signature alone is insufficient and failed attempt cannot be retried',async t=>{const x=await setup(t),c=x.c();const [s,r]=await proofs(x.b,c);assert.throws(()=>c.authorize(s,'',true),/encryption proof/);assert.throws(()=>c.authorize(s,r,true),/already used/);});
test('encryption proof from a different challenge is rejected',async t=>{const x=await setup(t),c=x.c(),other=x.c();const [s]=await proofs(x.b,c);const r=await x.b('open',{packet:other.packet});assert.throws(()=>c.authorize(s,r.message,true),/invalid encryption proof/);});
test('dual enrollment still enforces approval, signature and expiry',async t=>{const x=await setup(t),c=x.c();const [s,r]=await proofs(x.b,c);x.advance(30000);assert.throws(()=>c.authorize(s,r,true),/expired/);});
test('valid encryption proof does not bypass signature checking',async t=>{const x=await setup(t),c=x.c();const [,r]=await proofs(x.b,c);assert.throws(()=>c.authorize('0'.repeat(128),r,true),/device proof/);});
