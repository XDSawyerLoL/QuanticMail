// Trusted TLS endpoint is pinned in a private configuration file.
// No automatic retry, no fallback and no credential in argv.
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {config,check,exact,hex,port} from './pay-anchor-config.mjs';
import {assertExternalPayCheckpoint} from './pay-external-checkpoint.mjs';
const script=fileURLToPath(new URL('../../scripts/pay-anchor-request-lab.mjs',import.meta.url));
export function createPayAnchorClient({configFile,network,authorityPin}){
 const c=config(configFile);
 check(exact(c,['simulationOnly','network','authorityPin','port','token','certFile'])&&c.simulationOnly===true&&hex(network)&&hex(authorityPin)&&c.network===network&&c.authorityPin===authorityPin&&hex(c.token)&&port(c.port));
 function call(op,input){
  const b=Buffer.from(JSON.stringify(input));check(b.length<=8192);
  try{
   const p=spawnSync(process.execPath,[script,op,configFile],{input:b,encoding:'utf8',timeout:8000,maxBuffer:16384,windowsHide:true});
   check(!p.error&&p.status===0&&typeof p.stdout==='string'&&Buffer.byteLength(p.stdout)<=8192);
   return JSON.parse(p.stdout);
  }finally{b.fill(0);}
 }
 return Object.freeze({
  read(){const c=call('read',null);assertExternalPayCheckpoint(c,c);check(c.network===network&&c.authorityPin===authorityPin);return c;},
  compareAndSwap(before,after){assertExternalPayCheckpoint(before,before);assertExternalPayCheckpoint(after,after);check(before.network===network&&after.network===network&&before.authorityPin===authorityPin&&after.authorityPin===authorityPin);return call('cas',{before,after})===true;}
 });
}
