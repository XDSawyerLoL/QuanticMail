// One isolated laboratory operator, not an enrollment server. Keep the
// challenge state in this process; no replays or automatic policy mutations.
import {createInterface} from 'node:readline/promises';
import {createPrivateKey} from 'node:crypto';
import {open} from 'node:fs/promises';
import {constants} from 'node:fs';
import {resolve} from 'node:path';
import {prepareNativePossessionChallenge} from '../desktop/native-enrollment-possession.mjs';
const check=x=>{if(!x)throw Error('Operator refused');};
function readCode(s,prefix,max){
 check(typeof s==='string'&&s.startsWith(prefix)&&s.length<=max);
 const raw=s.slice(prefix.length);
 check(/^[A-Za-z0-9_-]+$/.test(raw));const b=Buffer.from(raw,'base64url');
 check(b.toString('base64url')===raw);return JSON.parse(b.toString('utf8'));
}
let rl;
try{
 const [keyPath,operatorPin,quorumPin,mode,rosterPath,rosterPin]=process.argv.slice(2);
 check(process.platform==='linux'&&process.stdin.isTTY&&process.stdout.isTTY&&[6,8].includes(process.argv.length)&&mode==='--synthetic-only'
 &&resolve(keyPath)===keyPath&&/^[a-f0-9]{64}$/.test(operatorPin)&&/^[a-f0-9]{64}$/.test(quorumPin));
 const f=await open(keyPath,constants.O_RDONLY|constants.O_NOFOLLOW);
 let secret;
 try{
  const st=await f.stat();check(st.isFile()&&st.nlink===1&&st.uid===process.getuid()&&(st.mode&0o077)===0&&st.size>0&&st.size<=16384);
  secret=await f.readFile();check(secret.length===st.size);
 }finally{await f.close();}
 let authorityKey;
 try{authorityKey=createPrivateKey(secret);}finally{secret.fill(0);}
 let voting={};
 if(rosterPath!==undefined){
  check(resolve(rosterPath)===rosterPath&&/^[a-f0-9]{64}$/.test(rosterPin));
  const file=await open(rosterPath,constants.O_RDONLY|constants.O_NOFOLLOW);
  try{
   const st=await file.stat();check(st.isFile()&&st.nlink===1&&st.size>0&&st.size<=8192);
   const bytes=await file.readFile();check(bytes.length===st.size);
   voting={trusted:JSON.parse(bytes.toString('utf8')),rosterPin};
  }finally{await file.close();}
 }
 rl=createInterface({input:process.stdin,output:process.stdout});
 const request=readCode((await rl.question('Candidature publique QSENROLL1 : ')).trim(),'QSENROLL1:',60000);
 const proof=prepareNativePossessionChallenge(request,{authorityKey,expectedAuthorityPin:operatorPin,quorumPin,...voting});
 process.stdout.write('Identite candidate : '+proof.challenge.address+'\nAppareil : '+proof.challenge.deviceId+'\n');
 check(await rl.question('Approuver la verification de cet appareil de laboratoire ? Saisir VERIFIER : ')==='VERIFIER');
 // No secret, bearer credential or private key in the invitation.
 process.stdout.write('QSPROOF1:'+Buffer.from(JSON.stringify(proof.challenge)).toString('base64url')+'\n');
 const reply=readCode((await rl.question('Preuve QSPROOFREPLY1 (avant expiration) : ')).trim(),'QSPROOFREPLY1:',16000);
 const approveEnrollment=rosterPath!==undefined&&(await rl.question('Confirmer le vote d inscription (liste de quatre autorites verifiee hors bande) ? Saisir APPROUVER : '))==='APPROUVER';
 const result=proof.verify(reply,{approved:true,approveEnrollment});
 if(result.vote)process.stdout.write('QSVOTE1:'+Buffer.from(JSON.stringify(result.vote)).toString('base64url')+'\n');
 process.stdout.write(JSON.stringify(result)+'\n');
 process.stdout.write('Preuve valide ; politique INACTIVE. Renouvellement signe independamment et approbation par quorum encore requis.\n');
}catch{
 process.stderr.write('Verification refusee. Aucun droit attribue ; aucun fichier de politique modifie.\n');process.exitCode=1;
}finally{rl?.close();}
