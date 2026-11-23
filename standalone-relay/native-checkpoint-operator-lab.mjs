// One process, one local authority. All inputs are individually immutable,
// pinned by an OUT-OF-BAND operator digest. No shared policy or relay database.
// Deliberately loopback-only: remote sites require independently configured
// authenticated tunnels; this laboratory does not expose an Internet listener.
import {createHash,createPrivateKey,createPublicKey,X509Certificate} from 'node:crypto';
import {lstat,readFile} from 'node:fs/promises';
import {resolve,join,basename} from 'node:path';
import {startNativeCheckpointAuthority} from './native-checkpoint-server.mjs';
import {createSignedAuthorityRenewalLab} from './native-authority-renewal-lab.mjs';
const check=x=>{if(!x)throw Error('Pinned native authority laboratory refused');};
const sha=b=>createHash('sha256').update(b).digest('hex');
const pin=/^[a-f0-9]{64}$/;
const id=/^authority-[a-z0-9-]{1,36}$/;
const files=['ca.pem','server.crt','server.key','signer.pem','state.json','policy.json'];
const fields=['caPin','tlsPin','signerPin','statePin','policyPin'];
const asObject=(o,keys)=>check(o&&typeof o==='object'&&!Array.isArray(o)&&Object.keys(o).length===keys.length&&keys.every(k=>Object.hasOwn(o,k)));
const boundJSON=(bytes,max)=>{check(Buffer.isBuffer(bytes)&&bytes.length>1&&bytes.length<=max);return JSON.parse(bytes.toString('utf8'));};
async function verifyFile(path,max,{secret=false}={}){
 const st=await lstat(path);
 check(st.isFile()&&!st.isSymbolicLink()&&st.size>=1&&st.size<=max&&st.nlink===1);
 if(secret)check((st.mode&0o077)===0);
 const data=await readFile(path);
 check(data.length===st.size);
 return data;
}
export async function loadPinnedAuthorityLab({directory,configPin}){
 check(process.platform==='linux'&&typeof directory==='string'&&directory===resolve(directory)&&!directory.includes('\0')
  &&basename(directory)!=='..'&&pin.test(configPin));
 const st=await lstat(directory);
 check(st.isDirectory()&&!st.isSymbolicLink()&&(st.mode&0o077)===0);
 const cfgBytes=await verifyFile(join(directory,'operator.json'),8192,{secret:true});
 check(sha(cfgBytes)===configPin);
 const cfg=boundJSON(cfgBytes,8192);
 const isV2=cfg?.format==='quantic-native-authority-operator-lab/v2';
 asObject(cfg,isV2?['format','labOnly','authorityId','port','pins','clientPins','renewalPublicKey']:
  ['format','labOnly','authorityId','port','pins','clientPins']);
 check((isV2||cfg.format==='quantic-native-authority-operator-lab/v1')
  &&cfg.labOnly===true&&id.test(cfg.authorityId)
  &&Number.isInteger(cfg.port)&&cfg.port>=0&&cfg.port<=65535);
 asObject(cfg.pins,fields);
 check(fields.every(f=>pin.test(cfg.pins[f])));
 check(Array.isArray(cfg.clientPins)&&cfg.clientPins.length>=1&&cfg.clientPins.length<=8
  &&cfg.clientPins.every(p=>pin.test(p))&&new Set(cfg.clientPins).size===cfg.clientPins.length);
 const data={};
 const limits=[65536,65536,16384,16384,1048576,262144];
 for(let i=0;i<files.length;i++){
  data[files[i]]=await verifyFile(join(directory,files[i]),limits[i],
   {secret:['server.key','signer.pem','policy.json','state.json'].includes(files[i])});
 }
 check(sha(data['ca.pem'])===cfg.pins.caPin);
 const tlsCert=new X509Certificate(data['server.crt']);
 check(sha(tlsCert.raw)===cfg.pins.tlsPin);
 const signer=createPrivateKey(data['signer.pem']);
 data['signer.pem'].fill(0);
 check(signer.asymmetricKeyType==='ed25519'
  &&sha(createPublicKey(signer).export({type:'spki',format:'der'}))===cfg.pins.signerPin);
 const key=data['server.key'];
 const state=boundJSON(data['state.json'],1048576);
 const policy=boundJSON(data['policy.json'],262144);
 check(sha(data['state.json'])===cfg.pins.statePin
  &&sha(data['policy.json'])===cfg.pins.policyPin);
 check(state.format==='quantic-relay-state'&&state.version===3
  &&Array.isArray(state.manifests)&&Array.isArray(state.cryptoProfiles)
  &&Array.isArray(policy)&&policy.length>=1&&policy.length<=1024);
 const now=Date.now(),saved=Date.parse(state.savedAt);
 check(Number.isFinite(saved)&&saved<=now&&(isV2||saved>now-30000));
 check(policy.every(p=>p&&typeof p==='object'&&p.active===true));
 let load=async()=>({state,policy});
 let renewalSequence=0;
 if(isV2){
  const key=Buffer.from(cfg.renewalPublicKey,'base64url');
  check(key.length===44&&key.toString('base64url')===cfg.renewalPublicKey);
  const pub=createPublicKey({key,format:'der',type:'spki'});
  check(pub.asymmetricKeyType==='ed25519'
   &&sha(key)!==cfg.pins.signerPin);
  const controller=await createSignedAuthorityRenewalLab({
   directory,authorityId:cfg.authorityId,configPin,
   initialStatePin:cfg.pins.statePin,initialPolicyPin:cfg.pins.policyPin,
   publicKey:cfg.renewalPublicKey,initialSnapshot:{state,policy}
  });
  // Every mTLS request checks the independently signed next generation
  // and durable monotonic head, then the existing 30-second freshness gate.
  load=controller.load;
  renewalSequence=controller.status().sequence;
 }
 return {authorityId:cfg.authorityId,port:cfg.port,signerPin:cfg.pins.signerPin,
  tlsPin:cfg.pins.tlsPin,clientPins:cfg.clientPins,renewalSequence,
  tls:{ca:data['ca.pem'],cert:data['server.crt'],key},
  privateKey:signer,load};
}
export async function startPinnedNativeAuthorityLab(args){
 const cfg=await loadPinnedAuthorityLab(args);
 const server=await startNativeCheckpointAuthority({
  tls:cfg.tls,privateKey:cfg.privateKey,clientPins:cfg.clientPins,
  port:cfg.port,load:cfg.load
 });
 return {authorityId:cfg.authorityId,port:server.port,signerPin:cfg.signerPin,
  tlsPin:cfg.tlsPin,close:server.close};
}
