// Trusted Windows controller adapter. Never expose this callback to a
// renderer or arbitrary network challenge. Use only the pinned mTLS client.
import {spawn} from 'node:child_process';
import {createHash} from 'node:crypto';
import {win32} from 'node:path';
import {createWindowsNativeStorage} from './native-windows-storage.mjs';
const check=x=>{if(!x)throw Error('Native Windows possession refused');};
const sha=b=>createHash('sha256').update(b).digest('hex');
export async function createWindowsEnrollmentProver({binary,binarySha256,dir,candidate,expected,signal}){
 const storage=await createWindowsNativeStorage({binary,binarySha256,dir});
 const digest=sha(JSON.stringify(candidate)),pins=structuredClone(expected);
 let busy=false;
 return async function prove(ch){
  check(!signal?.aborted&&!busy&&ch&&typeof ch.challenge==='string'&&Buffer.byteLength(ch.challenge)<=4096&&sha(ch.challenge)===ch.challengeSha256);
  const a=JSON.parse(ch.challenge);
  check(Array.isArray(a)&&a.length===14&&JSON.stringify(a)===ch.challenge&&a[0]==='quantic-native-enrollment-possession-lab/v1'&&a[9]===digest&&a[11]===ch.expires&&ch.expires>Date.now()&&ch.expires<=Date.now()+180000);
  check(['address','deviceId','signingPin','encryptionPin','kemPin','dsaPin','quorumPin','controllerPublic'].every((k,i)=>a[i+1]===pins[k]));
  busy=true;
  try{
   await storage.verifyBinary();
   const remaining=ch.expires-Date.now();check(!signal?.aborted&&remaining>0&&remaining<=180000);
   return await new Promise((resolve,reject)=>{
    const child=spawn(binary,['--prove-windows-enrollment-possession-gui-lab',dir,ch.challengeSha256],{shell:false,windowsHide:true,cwd:win32.dirname(binary),env:storage.env,stdio:['pipe','pipe','ignore']});
    const chunks=[];let n=0,done=false;
    const finish=(err,result)=>{if(done)return;done=true;clearTimeout(timer);signal?.removeEventListener('abort',fail);if(err){child.kill();reject(err);}else resolve(result);};
    const fail=()=>finish(Error('Native proof refused or cancelled'));
    const timer=setTimeout(fail,remaining);
    child.on('error',fail);child.stdin.on('error',fail);child.stdout.on('error',fail);
    child.stdout.on('data',b=>{n+=b.length;if(n>8192)fail();else chunks.push(b);});
    child.on('close',code=>{
     if(code!==0){fail();return;}
     try{
      const r=JSON.parse(Buffer.concat(chunks).toString('utf8'));
      check(r&&Object.keys(r).length===4&&r.status==='native-possession-lab-proof'&&r.challengeSha256===ch.challengeSha256);
      check(typeof r.classicalSignature==='string'&&/^[A-Za-z0-9_-]{86}$/.test(r.classicalSignature)&&typeof r.pqSignature==='string'&&/^[A-Za-z0-9_-]{4412}$/.test(r.pqSignature));
      finish(null,r);
     }catch{fail();}
    });
    signal?.addEventListener('abort',fail,{once:true});
    if(signal?.aborted){fail();return;}
    child.stdin.end(Buffer.from(ch.challenge,'utf8'));
   });
  }finally{busy=false;}
 };
}
