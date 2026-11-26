import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,createHash,sign,X509Certificate} from 'node:crypto';
import {mkdtemp,mkdir,writeFile,readFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {spawn,execFileSync} from 'node:child_process';
import {once} from 'node:events';
import {loadPinnedAuthorityLab} from '../standalone-relay/native-checkpoint-operator-lab.mjs';
import {authorityRenewalTranscript,initialAuthorityChain} from '../standalone-relay/native-authority-renewal-lab.mjs';
import {createAttestedPeerSource} from '../desktop/native-attested-peer.mjs';
import {canonicalManifestText} from '../lib/quantic/manifest-core.mjs';
import {canonicalCryptoProfileText} from '../lib/quantic/crypto-profile-core.mjs';

const sha=x=>createHash('sha256').update(x).digest('hex');
const spki=k=>k.publicKey.export({type:'spki',format:'der'});
const pub=k=>k.publicKey.export({format:'jwk'});
const ec=()=>generateKeyPairSync('ec',{namedCurve:'prime256v1'});
const fp=k=>sha('P-256:'+k.x+':'+k.y).slice(0,32);
function syntheticIdentity(){
 const owner=ec(),enc=ec(),deviceSign=ec();
 const root=generateKeyPairSync('ml-dsa-65'),kem=generateKeyPairSync('ml-kem-768'),deviceDsa=generateKeyPairSync('ml-dsa-65');
 const now=new Date().toISOString(),handle='pinnedtest';
 const address=handle+'~'+fp(pub(owner))+'@quantic';
 const deviceId='d-'+fp(pub(enc));
 const manifestPayload={version:1,sequence:1,canonicalAddress:address,handle,
  fingerprint:fp(pub(owner)),identityPublicKey:pub(enc),identitySigningPublicKey:pub(owner),
  devices:[{kind:'root',label:'pinned root',deviceId,publicKey:pub(enc),
   deviceSigningPublicKey:pub(deviceSign),issuedAt:now}],revocations:[],issuedAt:now};
 const manifest={format:'quantic-identity-manifest',version:1,payload:manifestPayload,
  signature:sign('sha256',Buffer.from(canonicalManifestText(manifestPayload)),
   {key:owner.privateKey,dsaEncoding:'ieee-p1363'}).toString('base64')};
 const profilePayload={version:2,sequence:1,canonicalAddress:address,
  identitySigningPublicKey:pub(owner),identityManifestSequence:1,policy:'hybrid-required',
  identityMlDsaAlgorithm:'ML-DSA-65',
  identityMlDsaPublicKeySpki:spki(root).toString('base64url'),
  devices:[{deviceId,mlKemAlgorithm:'ML-KEM-768',mlKemPublicKeySpki:spki(kem).toString('base64url'),
   mlDsaAlgorithm:'ML-DSA-65',mlDsaPublicKeySpki:spki(deviceDsa).toString('base64url')}],
  issuedAt:now};
 const canonical=Buffer.from(canonicalCryptoProfileText(profilePayload));
 const profile={format:'quantic-crypto-profile',version:2,payload:profilePayload,
  signatures:{p256:sign('sha256',canonical,{key:owner.privateKey,dsaEncoding:'ieee-p1363'}).toString('base64'),
   mlDsa65Self:sign(null,canonical,root.privateKey).toString('base64url')}};
 return {address,deviceId,manifest,profile,
  policy:{address,deviceId,rootPin:sha(spki(owner)),pqRootPin:sha(spki(root)),
   manifestSequence:1,profileSequence:1,
   manifestDigest:sha(canonicalManifestText(manifestPayload)),profileDigest:sha(canonical),
   active:true}};
}
function generateCerts(dir){
 const openssl=(...args)=>execFileSync('openssl',args,{cwd:dir,stdio:'ignore',timeout:10000});
 openssl('req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:prime256v1','-nodes',
  '-keyout','ca.key','-out','ca.crt','-subj','/CN=Quantic operator test CA','-days','1',
  '-addext','basicConstraints=critical,CA:TRUE');
 for(const name of ['client','w0','w1','w2','w3']){
  openssl('req','-new','-newkey','ec','-pkeyopt','ec_paramgen_curve:prime256v1','-nodes',
   '-keyout',name+'.key','-out',name+'.csr','-subj','/CN='+name,
   '-addext','subjectAltName=IP:127.0.0.1');
  openssl('x509','-req','-in',name+'.csr','-CA','ca.crt','-CAkey','ca.key',
   '-CAcreateserial','-out',name+'.crt','-days','1','-copy_extensions','copy');
 }
}
async function provisionAuthority(root,index,identity,clientPin){
 const name='w'+index,dir=join(root,'operator-'+index);
 await mkdir(dir,{mode:0o700});
 const signer=generateKeyPairSync('ed25519');
 const renewalSigner=generateKeyPairSync('ed25519');
 await mkdir(join(dir,'renewals'),{mode:0o700});
 const state={format:'quantic-relay-state',version:3,savedAt:new Date().toISOString(),
  manifests:[[identity.address,identity.manifest]],cryptoProfiles:[[identity.address,identity.profile]]};
 const fileData={
  'ca.pem':await readFile(join(root,'ca.crt')),
  'server.crt':await readFile(join(root,name+'.crt')),
  'server.key':await readFile(join(root,name+'.key')),
  'signer.pem':Buffer.from(signer.privateKey.export({type:'pkcs8',format:'pem'})),
  'state.json':Buffer.from(JSON.stringify(state)),
  'policy.json':Buffer.from(JSON.stringify([identity.policy]))
 };
 for(const [file,bytes] of Object.entries(fileData))
  await writeFile(join(dir,file),bytes,{mode:0o600,flag:'wx'});
 const cfg={
  format:'quantic-native-authority-operator-lab/v2',labOnly:true,
  authorityId:'authority-'+index,port:0,clientPins:[clientPin],
  renewalPublicKey:spki(renewalSigner).toString('base64url'),
  pins:{caPin:sha(fileData['ca.pem']),
   tlsPin:sha(new X509Certificate(fileData['server.crt']).raw),
   signerPin:sha(spki(signer)),statePin:sha(fileData['state.json']),
   policyPin:sha(fileData['policy.json'])}
 };
 const bytes=Buffer.from(JSON.stringify(cfg));
 await writeFile(join(dir,'operator.json'),bytes,{mode:0o600,flag:'wx'});
 return {dir,cfg,digest:sha(bytes),signer,renewalSigner,state};
}
async function boot(entry){
 const runner=resolve('scripts/run-native-checkpoint-authority-lab.mjs');
 const child=spawn(process.execPath,[runner,entry.dir,entry.digest],{
  stdio:['ignore','pipe','pipe'],env:{...process.env},windowsHide:true
 });
 let stderr='',stdout='';
 const ready=new Promise((resolveReady,reject)=>{
  const timer=setTimeout(()=>{child.kill();reject(Error('authority startup timeout: '+stderr));},10000);
  let done=false;
  const finish=(err,value)=>{
   if(done)return;done=true;clearTimeout(timer);
   err?reject(err):resolveReady(value);
  };
  child.stderr.on('data',b=>{stderr+=b.toString();if(stderr.length>16384)child.kill();});
  child.stdout.on('data',b=>{
   stdout+=b.toString();
   if(stdout.length>8192){child.kill();finish(Error('unbounded readiness frame'));return;}
   const n=stdout.indexOf('\n');
   if(n!==-1){
    try{const obj=JSON.parse(stdout.slice(0,n));assert.equal(obj.status,'local-synthetic-authority-ready');finish(null,obj);}
    catch(e){finish(e);}
   }
  });
  child.once('error',finish);
  child.once('exit',code=>finish(Error('authority exited without readiness '+code+': '+stderr)));
 });
 try{return {child,report:await ready};}
 catch(e){child.kill();throw e;}
}
async function stageRenewal(entry,identity,sequence,previousHash){
 const folder=join(entry.dir,'renewals',String(sequence).padStart(6,'0'));
 await mkdir(folder,{mode:0o700});
 const state={...entry.state,savedAt:new Date().toISOString()};
 const policy=[identity.policy];
 const sb=Buffer.from(JSON.stringify(state)),pb=Buffer.from(JSON.stringify(policy));
 const body={format:'quantic-native-authority-renewal/v1',
  authorityId:entry.cfg.authorityId,sequence,previousHash,
  stateHash:sha(sb),policyHash:sha(pb),savedAt:state.savedAt};
 const transcript=authorityRenewalTranscript(body);
 const signature=sign(null,transcript,entry.renewalSigner.privateKey).toString('base64url');
 for(const [name,data] of [['state.json',sb],['policy.json',pb],
  ['approval.json',Buffer.from(JSON.stringify({...body,signature}))]]){
  await writeFile(join(folder,name),data,{mode:0o600,flag:'wx'});
 }
 return sha(transcript);
}
async function stop(service){
 if(!service)return;
 const p=service.child;
 if(p.exitCode!==null||p.signalCode!==null)return;
 const exited=once(p,'exit');
 p.kill('SIGTERM');
 await exited;
}
test('four separately pinned OS processes enforce 3-of-4 mTLS quorum, crash cutoff, immutable state and key pins',
 {skip:process.platform!=='linux',timeout:180000},async()=>{
 const root=await mkdtemp(join(tmpdir(),'quantic-operator-')),services=[];
 try{
  generateCerts(root);
  const identity=syntheticIdentity();
  const clientCert=await readFile(join(root,'client.crt'));
  const clientPin=sha(new X509Certificate(clientCert).raw);
  const configs=[];
  for(let i=0;i<4;i++)configs.push(await provisionAuthority(root,i,identity,clientPin));
  const attested=[];
  for(const c of configs){
   const srv=await boot(c);services.push(srv);
   assert.equal(srv.report.signerPin,c.cfg.pins.signerPin);
   assert.equal(srv.report.tlsPin,c.cfg.pins.tlsPin);
   attested.push({url:'https://127.0.0.1:'+srv.report.port+'/native-checkpoint',
    pin:c.cfg.pins.signerPin,tlsPin:c.cfg.pins.tlsPin,
    publicKey:spki(c.signer).toString('base64url')});
  }
  assert.equal(new Set(services.map(s=>s.child.pid)).size,4);
  assert.equal(new Set(configs.map(c=>c.dir)).size,4);
  await assert.rejects(boot(configs[0]),/authority exited|readiness|operator authority/i,
   'a second independent process must never open the same v2 authority directory');
  let source=await createAttestedPeerSource({
   authorities:attested,caFile:join(root,'ca.crt'),
   clientCertFile:join(root,'client.crt'),clientKeyFile:join(root,'client.key')
  });
  const a=await source(identity.address,identity.deviceId);
  assert.equal(a.checkpoint.address,identity.address);
  assert.equal(a.contact.deviceId,identity.deviceId);
  const chains=[];
  for(const c of configs){
   chains.push(await stageRenewal(c,identity,1,
    initialAuthorityChain(c.cfg.authorityId,c.digest,c.cfg.pins.statePin,c.cfg.pins.policyPin)));
  }
  assert.equal((await source(identity.address,identity.deviceId)).contact.deviceId,identity.deviceId);
  for(let i=0;i<configs.length;i++){
   const h=JSON.parse(await readFile(join(configs[i].dir,'accepted-head.json'),'utf8'));
   assert.equal(h.sequence,1);assert.equal(h.chainHash,chains[i]);
  }
  // A stopped authority can be restarted, reconstruct the signed chain
  // from local disk and continue signing without lowering its sequence.
  await stop(services[3]);services.pop();
  const resumed=await boot(configs[3]);services.push(resumed);
  attested[3]={...attested[3],url:'https://127.0.0.1:'+resumed.report.port+'/native-checkpoint'};
  source=await createAttestedPeerSource({
   authorities:attested,caFile:join(root,'ca.crt'),
   clientCertFile:join(root,'client.crt'),clientKeyFile:join(root,'client.key')
  });
  assert.equal((await source(identity.address,identity.deviceId)).contact.deviceId,identity.deviceId);
  assert.equal(JSON.parse(await readFile(join(configs[3].dir,'accepted-head.json'),'utf8')).sequence,1);
  await stop(services[3]);services.pop();
  assert.equal((await source(identity.address,identity.deviceId)).contact.deviceId,identity.deviceId);
  await stop(services[2]);services.pop();
  await assert.rejects(source(identity.address,identity.deviceId));
  // Modified state or config cannot be loaded with stale independent pin.
  const c=configs[0];
  await writeFile(join(c.dir,'policy.json'),Buffer.from('[]'),{mode:0o600});
  await assert.rejects(loadPinnedAuthorityLab({directory:c.dir,configPin:c.digest}));
  await assert.rejects(loadPinnedAuthorityLab({directory:c.dir,configPin:'0'.repeat(64)}));
  // A stale state cannot sign a fresh checkpoint even if explicitly repinned.
  const stale=configs[1];
  const state=JSON.parse(await readFile(join(stale.dir,'state.json'),'utf8'));
  state.savedAt=new Date(Date.now()-31000).toISOString();
  const raw=Buffer.from(JSON.stringify(state));
  await writeFile(join(stale.dir,'state.json'),raw);
  const cfg={...stale.cfg,pins:{...stale.cfg.pins,statePin:sha(raw)}};
  const cb=Buffer.from(JSON.stringify(cfg));await writeFile(join(stale.dir,'operator.json'),cb);
  await assert.rejects(loadPinnedAuthorityLab({directory:stale.dir,configPin:sha(cb)}));
 }finally{
  await Promise.all(services.map(stop));
  await rm(root,{recursive:true,force:true});
 }
});
