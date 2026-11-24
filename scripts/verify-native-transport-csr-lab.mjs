import {open} from 'node:fs/promises';
import {constants} from 'node:fs';
import {createHash} from 'node:crypto';
import {verifyNativeTransportRequest} from '../desktop/native-transport-csr.mjs';
try{
 const [file,pin,flag]=process.argv.slice(2);
 if(process.platform!=='linux'||process.argv.length!==5||flag!=='--synthetic-only'||!/^[a-f0-9]{64}$/.test(pin))throw Error('Lab only');
 const f=await open(file,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);let raw;
 try{const s=await f.stat();if(!s.isFile()||s.size<1||s.size>131072)throw Error('Invalid input');raw=await f.readFile();if(raw.length!==s.size||createHash('sha256').update(raw).digest('hex')!==pin)throw Error('Wrong pin');}finally{await f.close();}
 const c=JSON.parse(raw.toString('utf8'));
 function code(s,p){if(typeof s!=='string'||!s.startsWith(p)||s.length>60000)throw Error('Invalid code');const b=Buffer.from(s.slice(p.length),'base64url');if(b.toString('base64url')!==s.slice(p.length))throw Error('Invalid code');return JSON.parse(b.toString('utf8'));}
 const request=code(c.request,'QSENROLL1:'),approvals=code(c.approvals,'QSAPPROVAL1:'),credential=code(c.credential,'QSCRED1:'),csr=code(c.transport,'QSTLS1:');
 const result=verifyNativeTransportRequest(request,approvals.votes,{trusted:approvals.trusted,rosterPin:c.rosterPin,quorumPin:c.quorumPin},credential,csr);
 process.stdout.write(JSON.stringify(result)+'\n');
}catch{process.stderr.write('Transport requests refused. No certificate issued.\n');process.exitCode=1;}
