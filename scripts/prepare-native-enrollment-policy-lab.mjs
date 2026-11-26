// An operator-side offline preparation tool. No identity database mutation,
// no automatic renewal signature, no fabricated snapshot date. The input
// configuration digest MUST be authenticated out of band by this operator.
import {createHash} from 'node:crypto';
import {open} from 'node:fs/promises';
import {constants} from 'node:fs';
import {resolve} from 'node:path';
import {prepareQuorumEnrollmentPolicy} from '../desktop/native-enrollment-quorum.mjs';
const check=x=>{if(!x)throw Error('Enrollment policy preparation refused');};
const hex=/^[a-f0-9]{64}$/;
const sha=x=>createHash('sha256').update(x).digest('hex');
async function readPinned(path,pin,max){
 check(typeof path==='string'&&resolve(path)===path&&hex.test(pin));
 const fd=await open(path,constants.O_RDONLY|constants.O_NOFOLLOW);
 try{
  const st=await fd.stat();check(st.isFile()&&st.nlink===1&&st.size>0&&st.size<=max);
  const b=await fd.readFile();check(b.length===st.size&&sha(b)===pin);
  return JSON.parse(b.toString('utf8'));
 }finally{await fd.close();}
}
try{
 const [file,configPin,mode]=process.argv.slice(2);
 check(process.platform==='linux'&&process.argv.length===5&&mode==='--synthetic-only');
 const c=await readPinned(file,configPin,131072);
 check(c?.format==='quantic-native-enrollment-policy-preparation-lab/v1'&&c.labOnly===true&&c.approved===true);
 const [state,previousPolicy]=await Promise.all([
  readPinned(c.stateFile,c.statePin,1048576),
  readPinned(c.previousPolicyFile,c.previousPolicyPin,262144)
 ]);
 const result=prepareQuorumEnrollmentPolicy(c.request,c.votes,{trusted:c.trusted,rosterPin:c.rosterPin,quorumPin:c.quorumPin,state,previousPolicy,approved:true});
 // Output exclusively the policy for the next operator-approved renewal.
 // The caller can review/save it; the service will not read it automatically.
 process.stdout.write(JSON.stringify(result.policy)+'\n');
 process.stderr.write('Politique de laboratoire preparee pour '+result.approvals+' approbations. Publication NON effectuee. Renouvellement signe requis.\n');
}catch{
 process.stderr.write('Preparation refusee : aucun compte active ni fichier modifie.\n');process.exitCode=1;
}
