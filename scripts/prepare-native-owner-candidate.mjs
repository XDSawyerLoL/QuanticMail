// Offline owner workstation only. No HTTP, relay credentials or private
// device keys. Existing independently protected ownership keys are required.
import {createHash,createPrivateKey,createPublicKey} from 'node:crypto';
import {open,lstat,realpath} from 'node:fs/promises';
import {constants} from 'node:fs';
import {join,resolve} from 'node:path';
import {nativeOwnerAddress,prepareNativeIdentityCandidate} from '../lib/quantic/native-owner-candidate.mjs';
const check=x=>{if(!x)throw Error('Offline identity candidate refused');};
const sha=b=>createHash('sha256').update(b).digest('hex');
const pin=/^[a-f0-9]{64}$/;
async function privateFile(dir,name,max){
 const fd=await open(join(dir,name),constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
 try{
  const st=await fd.stat();
  check(st.isFile()&&st.nlink===1&&st.uid===process.getuid()&&(st.mode&0o077)===0&&st.size>=1&&st.size<=max);
  const b=Buffer.alloc(st.size+1);let n=0;
  while(n<b.length){const r=await fd.read(b,n,b.length-n,null);if(r.bytesRead===0)break;n+=r.bytesRead;}
  if(n!==st.size){b.fill(0);throw Error('File changed');}
  return b.subarray(0,n);
 }finally{await fd.close();}
}
async function privateKey(dir,name){
 const b=await privateFile(dir,name,32768);
 try{return createPrivateKey(b);}finally{b.fill(0);}
}
try{
 const [mode,dir,handle,digest]=process.argv.slice(2);
 check(process.platform==='linux'&&Number(process.versions.node.split('.')[0])>=24&&typeof dir==='string'&&resolve(dir)===dir&&await realpath(dir)===dir);
 const st=await lstat(dir);check(st.isDirectory()&&st.uid===process.getuid()&&(st.mode&0o077)===0);
 if(mode==='address'){
  check(process.argv.length===5);
  const raw=await privateFile(dir,'owner-signing-public.pem',16384);
  const owner=createPublicKey(raw);
  process.stdout.write(JSON.stringify({status:'owner-address-only',address:nativeOwnerAddress(handle,owner),rootPin:sha(owner.export({type:'spki',format:'der'})),labOnly:true})+'\n');
 }else{
  check(mode==='prepare'&&process.argv.length===6&&pin.test(digest));
  const approval=await privateFile(dir,'approved-device-pins.json',8192);
  check(sha(approval)===digest);
  const expected=JSON.parse(approval.toString('utf8'));
  const record=JSON.parse((await privateFile(dir,'identity-public.json',16384)).toString('utf8'));
  const ownerSigning=await privateKey(dir,'owner-signing.pem');
  const ownerPQ=await privateKey(dir,'owner-pq.pem');
  const candidate=prepareNativeIdentityCandidate({labOnly:true,handle,record,expected,ownerSigning,ownerPQ});
  const out=await open(join(dir,'identity-candidate.json'),'wx',0o600);
  try{await out.writeFile(JSON.stringify(candidate)+'\n');await out.sync();}finally{await out.close();}
  const parent=await open(dir,'r');try{await parent.sync();}finally{await parent.close();}
  process.stdout.write(JSON.stringify({status:'root-signed-candidate-staged-inactive',address:expected.address,deviceId:expected.deviceId,registrationAuthorized:false})+'\n');
 }
}catch{
 process.stderr.write('Offline candidate refused. Preserve existing keys and files. No registration or automatic retry.\n');
 process.exitCode=1;
}
