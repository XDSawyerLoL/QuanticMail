// Operator-side verification only. CSR signatures are verified by the local
// OpenSSL executable; the CA operator decides independently whether to issue.
import {createHash,createPublicKey,verify} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {verifyNativeEnrollmentQuorum} from './native-enrollment-quorum.mjs';
const check=x=>{if(!x)throw Error('Native transport request refused');};
const hash=x=>createHash('sha256').update(x).digest('hex');
function decode(s,max){
 check(typeof s==='string'&&s.length<=Math.ceil(max/3)*4&&/^[A-Za-z0-9_-]+$/.test(s));
 const b=Buffer.from(s,'base64url');check(b.length>0&&b.length<=max&&b.toString('base64url')===s);return b;
}
export function verifyNativeTransportRequest(request,votes,options,credential,csr){
 const q=verifyNativeEnrollmentQuorum(request,votes,options);
 check(csr&&Object.keys(csr).length===6&&csr.format==='quantic-native-transport-csr-lab/v1'&&csr.requestDigest===q.requestDigest&&csr.tokenHash===credential?.tokenHash&&/^[a-f0-9]{64}$/.test(csr.tokenHash));
 const controller=createPublicKey({key:Buffer.concat([Buffer.from('302a300506032b6570032100','hex'),decode(request.controllerPublic,32)]),type:'spki',format:'der'});
 const raw=x=>Buffer.from(JSON.stringify(x));
 check(verify(null,raw(['quantic-native-mailbox-credential-lab/v1',q.requestDigest,csr.tokenHash]),controller,decode(credential.signature,64)));
 check(verify(null,raw([csr.format,csr.requestDigest,csr.tokenHash,hash(csr.anchorCsr),hash(csr.checkpointCsr)]),controller,decode(csr.signature,64)));
 const items=[];
 for(const [role,encoded] of [['anchor',csr.anchorCsr],['checkpoint',csr.checkpointCsr]]){
  const der=decode(encoded,4096);
  const run=args=>{const r=spawnSync('openssl',['req','-inform','DER',...args],{input:der,timeout:5000,maxBuffer:16384,windowsHide:true,env:{PATH:'/usr/bin:/bin'}});check(r.status===0&&!r.error);return r;};
  // OpenSSL versions differ in exit behavior for an invalid self-signature;
  // additionally require an explicit successful verification diagnostic.
  const result=run(['-verify','-noout']);
  const diagnostic=Buffer.concat([result.stdout,result.stderr]).toString('utf8').trim();
  check(/^(?:Certificate request )?self-signature verify OK$/i.test(diagnostic));
  const subject=run(['-subject','-nameopt','RFC2253','-noout']).stdout.toString('utf8').trim();
  check(subject==='subject=CN=quantic-lab-'+role+'-'+q.requestDigest.slice(0,32));
  const pem=run(['-pubkey','-noout']).stdout;
  const key=createPublicKey(pem);check(key.asymmetricKeyType==='ec'&&key.asymmetricKeyDetails?.namedCurve==='prime256v1');
  items.push({role,publicKeyPin:hash(key.export({type:'spki',format:'der'})),csrPem:run(['-outform','PEM']).stdout.toString('utf8')});
 }
 check(items[0].publicKeyPin!==items[1].publicKeyPin);
 return {status:'transport-requests-verified-pending-ca-approval',labOnly:true,requestDigest:q.requestDigest,requests:items,mailAuthorized:false};
}
