// One explicit, isolated OPERATOR approval, never a relay service.
// An independently pinned Ed25519 renewal key signs the exact snapshot and
// policy bytes prepared by the operator; approval.json is written LAST.
// This does not generate or "freshen" a relay savedAt timestamp.
import {createHash,createPrivateKey,createPublicKey,sign} from 'node:crypto';
import {readFile,lstat,open} from 'node:fs/promises';
import {resolve,join,sep} from 'node:path';
import {authorityRenewalTranscript} from './native-authority-renewal-lab.mjs';
const check=x=>{if(!x)throw Error('Native authority operator approval refused');};
const hash=x=>createHash('sha256').update(x).digest('hex');
const hex=/^[a-f0-9]{64}$/;
const fields=(o,a)=>check(o&&typeof o==='object'&&!Array.isArray(o)
 &&Object.keys(o).length===a.length&&a.every(k=>Object.hasOwn(o,k)));
async function privateFile(path,max){
 const st=await lstat(path);
 check(st.isFile()&&!st.isSymbolicLink()&&st.nlink===1
  &&(st.mode&0o077)===0&&st.size>1&&st.size<=max);
 const b=await readFile(path);
 check(b.length===st.size);
 return b;
}
export async function approveNativeAuthorityRenewalLab({
 directory,configPin,operatorKeyFile,sequence,previousHash,now=Date.now()
}){
 check(process.platform==='linux'&&typeof directory==='string'
  &&typeof operatorKeyFile==='string'&&resolve(directory)===directory
  &&resolve(operatorKeyFile)===operatorKeyFile
  &&!operatorKeyFile.startsWith(directory+sep)
  &&hex.test(configPin)&&hex.test(previousHash)
  &&Number.isInteger(sequence)&&sequence>=1&&sequence<=999999
  &&Number.isSafeInteger(now));
 const root=await lstat(directory);
 check(root.isDirectory()&&!root.isSymbolicLink()&&(root.mode&0o077)===0);
 const opBytes=await privateFile(join(directory,'operator.json'),8192);
 check(hash(opBytes)===configPin);
 const cfg=JSON.parse(opBytes.toString('utf8'));
 fields(cfg,['format','labOnly','authorityId','port','pins','clientPins','renewalPublicKey']);
 check(cfg.format==='quantic-native-authority-operator-lab/v2'&&cfg.labOnly===true);
 const keyBuffer=await privateFile(operatorKeyFile,16384);
 let signer;
 try{signer=createPrivateKey(keyBuffer);}finally{keyBuffer.fill(0);}
 check(signer.asymmetricKeyType==='ed25519');
 const publicKey=createPublicKey(signer).export({type:'spki',format:'der'}).toString('base64url');
 check(publicKey===cfg.renewalPublicKey);
 const head=JSON.parse((await privateFile(join(directory,'accepted-head.json'),4096)).toString('utf8'));
 fields(head,['format','sequence','chainHash']);
 check(head.format==='quantic-native-authority-head/v1'
  &&head.sequence===sequence-1&&head.chainHash===previousHash);
 const dir=join(directory,'renewals',String(sequence).padStart(6,'0'));
 const st=await lstat(dir);
 check(st.isDirectory()&&!st.isSymbolicLink()&&(st.mode&0o077)===0);
 const [sb,pb]=await Promise.all([
  privateFile(join(dir,'state.json'),1048576),
  privateFile(join(dir,'policy.json'),262144)
 ]);
 const state=JSON.parse(sb.toString('utf8')),policy=JSON.parse(pb.toString('utf8'));
 const saved=Date.parse(state.savedAt);
 check(state?.format==='quantic-relay-state'&&state.version===3
  &&Array.isArray(state.manifests)&&Array.isArray(state.cryptoProfiles)
  &&Array.isArray(policy)&&policy.length>=1&&policy.length<=1024
  &&policy.every(p=>p&&typeof p.active==='boolean')
  &&Number.isFinite(saved)&&new Date(saved).toISOString()===state.savedAt
  &&saved<=now&&saved>now-30000);
 const body={format:'quantic-native-authority-renewal/v1',
  authorityId:cfg.authorityId,sequence,previousHash,
  stateHash:hash(sb),policyHash:hash(pb),savedAt:state.savedAt};
 const transcript=authorityRenewalTranscript(body);
 const signature=sign(null,transcript,signer).toString('base64url');
 const path=join(dir,'approval.json');
 // Exclusive creation: an existing (including partial) approval is never
 // overwritten silently. If power is lost, the operator must reconcile it.
 const fd=await open(path,'wx',0o600);
 try{await fd.writeFile(JSON.stringify({...body,signature}));await fd.sync();}
 finally{await fd.close();}
 const parent=await open(dir,'r');
 try{await parent.sync();}finally{await parent.close();}
 return Object.freeze({status:'independent-lab-renewal-signed',
  authorityId:cfg.authorityId,sequence,approvalDigest:hash(transcript),
  labOnly:true,liveEnrollmentAuthorized:false});
}
