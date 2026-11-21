// One bounded helper process, four independently authenticated TLS requests.
// All responses collected; no retries, early quorum return or downgrade.
import {readFileSync} from 'node:fs';
import {requestPayAnchor} from './pay-anchor-request-lab.mjs';
import {check,exact,hex} from '../lib/quantic/pay-anchor-config.mjs';
async function main(){
 check(process.argv.length===3&&['read','cas'].includes(process.argv[2]));
 const raw=readFileSync(0);check(raw.length<=65536);
 let x;try{x=JSON.parse(raw.toString('utf8'));}finally{raw.fill(0);}
 check(exact(x,['members','input'])&&Array.isArray(x.members)&&x.members.length===4);
 for(const m of x.members)check(m===null||exact(m,['path','config','certHash'])&&typeof m.path==='string'&&typeof m.config==='string'&&hex(m.certHash));
 const results=await Promise.all(x.members.map(async m=>{
  if(m===null)return {ok:false};
  try{return {ok:true,value:await requestPayAnchor(process.argv[2],m.path,x.input,m)};}catch{return {ok:false};}
 }));
 const output=JSON.stringify(results);check(Buffer.byteLength(output)<=65536);
 process.stdout.write(output);
}
main().catch(()=>{console.error('Pay anchor batch refused');process.exitCode=1;});
