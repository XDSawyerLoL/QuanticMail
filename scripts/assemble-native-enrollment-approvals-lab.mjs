// Local operator: public votes only. No key or token generation.
import {readFile} from 'node:fs/promises';
import {verifyNativeEnrollmentQuorum} from '../desktop/native-enrollment-quorum.mjs';
function decode(code,prefix){
 if(typeof code!=='string'||!code.startsWith(prefix)||code.length>60000)throw Error('Invalid code');
 const s=code.slice(prefix.length),b=Buffer.from(s,'base64url');
 if(b.toString('base64url')!==s)throw Error('Invalid code');
 return JSON.parse(b.toString('utf8'));
}
try{
 const [file,rosterPin,quorumPin,flag]=process.argv.slice(2);
 if(process.argv.length!==6||flag!=='--synthetic-only')throw Error('Lab only');
 const raw=await readFile(file);if(raw.length>131072)throw Error('Too large');
 const c=JSON.parse(raw.toString('utf8'));
 const request=decode(c.request,'QSENROLL1:'),votes=c.votes.map(v=>decode(v,'QSVOTE1:'));
 verifyNativeEnrollmentQuorum(request,votes,{trusted:c.trusted,rosterPin,quorumPin});
 const bundle={format:'quantic-enrollment-approvals-lab/v1',trusted:c.trusted.map(({pin,publicKey})=>({pin,publicKey})),votes};
 process.stdout.write('QSAPPROVAL1:'+Buffer.from(JSON.stringify(bundle)).toString('base64url')+'\n');
}catch{process.stderr.write('Approval bundle refused.\n');process.exitCode=1;}
