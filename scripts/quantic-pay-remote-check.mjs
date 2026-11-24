// Read-only Windows operator verification. Does not sign or initiate payments.
// Configuration is public only; individual carrier tokens are provided in the
// independently protected lab coordinator (not this offline diagnostic).
import {spawnSync} from 'node:child_process';
import {isAbsolute} from 'node:path';
import {summarizePayProofs} from '../lib/quantic/pay-lab-checkpoint.mjs';
const [binary,dir,signingPin,pqPin]=process.argv.slice(2);
if(process.platform!=='win32'||process.argv.length!==6||!isAbsolute(binary)||!isAbsolute(dir)||!(/^[a-f0-9]{64}$/).test(signingPin)||!(/^[a-f0-9]{64}$/).test(pqPin))throw Error('Explicit Windows lab required');
const r=spawnSync(binary,['--read-windows-pay-history-lab',dir],{shell:false,stdio:['ignore','pipe','ignore'],encoding:'utf8',maxBuffer:4*1024*1024,timeout:10000});
if(r.status!==0||r.error)throw Error('Native history refused');
const result=summarizePayProofs(JSON.parse(r.stdout),{signingPin,pqPin});
console.log(JSON.stringify({...result,realPaymentAuthorized:false,localHistoryOnly:true}));
