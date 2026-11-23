// Explicit independently signed laboratory snapshot renewals. v1 only.
// Each authority has its OWN operator signer, approval chain, and durable head.
// The original snapshot stays immutable; new generations are only accepted
// after a DIFFERENT, pinned Ed25519 key signs the exact bytes and parent hash.
// There is no HTTP update endpoint and no automatic timestamp fabrication.
import {createHash,createPublicKey,randomBytes,verify} from 'node:crypto';
import {lstat,readFile,open,rename,unlink} from 'node:fs/promises';
import {join,resolve,dirname} from 'node:path';
const refuse=()=>{throw Error('Native authority signed snapshot renewal refused');};
const check=x=>{if(!x)refuse();};
const hash=b=>createHash('sha256').update(b).digest('hex');
const hex=/^[a-f0-9]{64}$/;
const dirName=n=>String(n).padStart(6,'0');
const MAX=999999;
const exact=(o,fields)=>check(o&&typeof o==='object'&&!Array.isArray(o)
 &&Object.keys(o).length===fields.length&&fields.every(f=>Object.hasOwn(o,f)));
const json=(b,max)=>{check(Buffer.isBuffer(b)&&b.length>1&&b.length<=max);return JSON.parse(b.toString('utf8'));};
async function checked(path,max,{directory=false}={}){
 const s=await lstat(path);
 check(!s.isSymbolicLink()&&(s.mode&0o077)===0&&s[directory?'isDirectory':'isFile']());
 if(!directory)check(s.nlink===1&&s.size>=1&&s.size<=max);
 return s;
}
async function readPrivate(path,max){
 const s=await checked(path,max);
 const b=await readFile(path);
 check(b.length===s.size);
 return b;
}
async function optional(path,max){
 try{return await readPrivate(path,max);}
 catch(e){if(e?.code==='ENOENT')return null;throw e;}
}
export const initialAuthorityChain=(authorityId,configPin,statePin,policyPin)=>{
 check(typeof authorityId==='string'&&[configPin,statePin,policyPin].every(v=>hex.test(v)));
 return hash(Buffer.from(JSON.stringify(['quantic-native-authority-chain-root/v1',authorityId,configPin,statePin,policyPin])));
};
export const authorityRenewalTranscript=p=>{
 exact(p,['format','authorityId','sequence','previousHash','stateHash','policyHash','savedAt']);
 check(p.format==='quantic-native-authority-renewal/v1'
  &&/^authority-[a-z0-9-]{1,36}$/.test(p.authorityId)
  &&Number.isSafeInteger(p.sequence)&&p.sequence>=1&&p.sequence<=MAX
  &&[p.previousHash,p.stateHash,p.policyHash].every(x=>hex.test(x))
  &&typeof p.savedAt==='string'&&new Date(p.savedAt).toISOString()===p.savedAt);
 return Buffer.from(JSON.stringify(['quantic-native-authority-renewal/v1',
  p.authorityId,p.sequence,p.previousHash,p.stateHash,p.policyHash,p.savedAt]));
};
function parseApproval(raw){
 const p=json(raw,8192);
 exact(p,['format','authorityId','sequence','previousHash','stateHash','policyHash','savedAt','signature']);
 check(typeof p.signature==='string'&&/^[A-Za-z0-9_-]{86}$/.test(p.signature));
 const sig=Buffer.from(p.signature,'base64url');
 check(sig.length===64&&sig.toString('base64url')===p.signature);
 const {signature,...body}=p;
 return {body,sig,transcript:authorityRenewalTranscript(body)};
}
async function durableHead(path,value){
 const tmp=path+'.tmp-'+randomBytes(12).toString('hex');
 let fd;
 try{
  fd=await open(tmp,'wx',0o600);
  await fd.writeFile(Buffer.from(JSON.stringify(value)));
  await fd.sync();await fd.close();fd=undefined;
  await rename(tmp,path);
  const parent=await open(dirname(path),'r');
  try{await parent.sync();}finally{await parent.close();}
 }catch(e){
  try{await fd?.close();}catch{}
  await unlink(tmp).catch(()=>{});
  throw e;
 }
}
export async function createSignedAuthorityRenewalLab({
 directory,authorityId,configPin,initialStatePin,initialPolicyPin,publicKey,
 initialSnapshot,now=()=>Date.now()
}){
 check(typeof directory==='string'&&resolve(directory)===directory);
 check(hex.test(configPin)&&hex.test(initialStatePin)&&hex.test(initialPolicyPin));
 const rawKey=Buffer.from(publicKey,'base64url');
 check(rawKey.length===44&&rawKey.toString('base64url')===publicKey);
 const operator=createPublicKey({key:rawKey,format:'der',type:'spki'});
 check(operator.asymmetricKeyType==='ed25519');
 const root=initialAuthorityChain(authorityId,configPin,initialStatePin,initialPolicyPin);
 const headPath=join(directory,'accepted-head.json');
 const renewals=join(directory,'renewals');
 await checked(renewals,0,{directory:true});
 const checkSnapshot=(state,policy,{savedAt,requireFresh=true}={})=>{
  check(state?.format==='quantic-relay-state'&&state.version===3
   &&Array.isArray(state.manifests)&&Array.isArray(state.cryptoProfiles)
   &&Array.isArray(policy)&&policy.length>=1&&policy.length<=1024
   &&policy.every(p=>p&&typeof p==='object'&&typeof p.active==='boolean'));
  const observed=Date.parse(state.savedAt);
  check(Number.isFinite(observed)&&state.savedAt===savedAt
   &&observed<=now()&&(!requireFresh||observed>now()-30000));
 };
 checkSnapshot(initialSnapshot.state,initialSnapshot.policy,{
  savedAt:initialSnapshot.state.savedAt,requireFresh:false
 });
 async function candidate(sequence,previousHash,{fresh=true}={}){
  const dir=join(renewals,dirName(sequence));
  await checked(dir,0,{directory:true});
  const approval=parseApproval(await readPrivate(join(dir,'approval.json'),8192));
  const p=approval.body;
  check(p.authorityId===authorityId&&p.sequence===sequence&&p.previousHash===previousHash
   &&verify(null,approval.transcript,operator,approval.sig));
  const [sb,pb]=await Promise.all([
   readPrivate(join(dir,'state.json'),1048576),
   readPrivate(join(dir,'policy.json'),262144)
  ]);
  check(hash(sb)===p.stateHash&&hash(pb)===p.policyHash);
  const state=json(sb,1048576),policy=json(pb,262144);
  checkSnapshot(state,policy,{savedAt:p.savedAt,requireFresh:fresh});
  return {state,policy,chainHash:hash(approval.transcript),sequence};
 }
 const initialHead={format:'quantic-native-authority-head/v1',sequence:0,chainHash:root};
 let saved=await optional(headPath,4096);
 if(!saved){
  // The first boot creates a durable head. A missing head with existing
  // historical generations is refused, preventing silent reset.
  let first;
  try{first=await lstat(join(renewals,dirName(1)));}catch(e){if(e?.code!=='ENOENT')throw e;}
  check(!first);
  // Exclusive create: another operator's concurrent boot must fail.
  const handle=await open(headPath,'wx',0o600);
  try{await handle.writeFile(JSON.stringify(initialHead));await handle.sync();}
  finally{await handle.close();}
  const parent=await open(directory,'r');
  try{await parent.sync();}finally{await parent.close();}
  saved=await readPrivate(headPath,4096);
 }
 const head=json(saved,4096);
 const validateHead=h=>{
  exact(h,['format','sequence','chainHash']);
  check(h.format==='quantic-native-authority-head/v1'
   &&Number.isSafeInteger(h.sequence)&&h.sequence>=0&&h.sequence<=MAX
   &&hex.test(h.chainHash));
 };
 validateHead(head);
 let current=initialSnapshot,chain=root,sequence=0;
 for(let n=1;n<=head.sequence;n++){
  const r=await candidate(n,chain,{fresh:false});
  current={state:r.state,policy:r.policy};chain=r.chainHash;sequence=n;
 }
 check(head.chainHash===chain);
 let lastHash=chain;
 let lock=Promise.resolve();
 async function loadLatest(){
  const onDisk=json(await readPrivate(headPath,4096),4096);
  validateHead(onDisk);
  check(onDisk.sequence===sequence&&onDisk.chainHash===lastHash);
  if(sequence<MAX){
   const dir=join(renewals,dirName(sequence+1));
   const next=await optional(join(dir,'approval.json'),8192);
   if(next!==null){
    // Reads the same verified approval twice; the separately pinned
    // signature and digests make a replacement fail closed.
    const r=await candidate(sequence+1,lastHash);
    const newHead={format:initialHead.format,sequence:r.sequence,chainHash:r.chainHash};
    await durableHead(headPath,newHead); // durability BEFORE serving
    current={state:r.state,policy:r.policy};
    sequence=r.sequence;lastHash=r.chainHash;
   }
  }
  // Every request still goes through issueCheckpoint's 30s fresh-state
  // check, so a missed renewal NEVER extends an old snapshot's validity.
  return current;
 }
 return {
  load(){
   const job=lock.then(loadLatest);
   lock=job.then(()=>{},()=>{});
   return job;
  },
  status:()=>Object.freeze({sequence,chainHash:lastHash,labOnly:true}),
  operatorPublicKeyPin:hash(rawKey)
 };
}
