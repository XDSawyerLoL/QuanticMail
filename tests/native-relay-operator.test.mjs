import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {mkdtemp,mkdir,writeFile,readFile,access,rm,realpath} from 'node:fs/promises';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {loadPinnedNativeRelay,startPinnedNativeRelay} from '../standalone-relay/native-relay-operator.mjs';
const sha=x=>createHash('sha256').update(x).digest('hex');
const linux=process.platform==='linux';
async function fixture(){
 const root=await realpath(await mkdtemp(join(tmpdir(),'qs-relay-operator-')));
 const configDir=join(root,'config'),dataDir=join(root,'state');await mkdir(configDir,{mode:0o700});await mkdir(dataDir,{mode:0o700});
 const authority={authorities:[]},tlsFilePins={};
 for(const k of ['caFile','clientCertFile','clientKeyFile']){
  const path=join(configDir,k+'.pem'),b=Buffer.from('synthetic fixture '+k);
  await writeFile(path,b,{mode:0o600});authority[k]=path;tlsFilePins[k]=sha(b);
 }
 const config={format:'quantic-private-native-relay/v1',labOnly:true,dataDir,port:49001,authority,tlsFilePins};
 const file=join(configDir,'relay.json'),bytes=Buffer.from(JSON.stringify(config));await writeFile(file,bytes,{mode:0o600});
 return{root,config,args:{file,pin:sha(bytes)},lock:join(dataDir,'.native-relay-active.lock'),cleanup:()=>rm(root,{recursive:true,force:true})};
}
test('pinned relay refuses modified config and modified TLS file',{skip:!linux},async()=>{
 const f=await fixture();
 try{
  await assert.rejects(loadPinnedNativeRelay({...f.args,pin:'0'.repeat(64)}));
  const {readTLS}=await loadPinnedNativeRelay(f.args);
  assert.equal((await readTLS(f.config.authority.caFile)).toString(),'synthetic fixture caFile');
  await writeFile(f.config.authority.caFile,'tampered');
  await assert.rejects(readTLS(f.config.authority.caFile));
  await assert.rejects(readTLS('/etc/passwd'));
 }finally{await f.cleanup();}
});
test('single relay directory lock, loopback-only, graceful release and fail-closed startup',{skip:!linux},async()=>{
 const f=await fixture();let opened=0,closed=0;
 const deps={makePeerSource:async(cfg,{read})=>{assert.ok(await read(cfg.caFile));return async()=>{};},
 startRelay:async opts=>{opened++;assert.equal(opts.host,'127.0.0.1');assert.equal(opts.dataDir,f.config.dataDir);assert.equal(typeof opts.nativePeerSource,'function');return {port:opts.port,relayId:'a'.repeat(64),close:async()=>{closed++;}};}};
 try{
  const x=await startPinnedNativeRelay(f.args,deps);await access(f.lock);
  await assert.rejects(startPinnedNativeRelay(f.args,deps));assert.equal(opened,1);
  await x.close();await assert.rejects(access(f.lock));assert.equal(closed,1);
  const y=await startPinnedNativeRelay(f.args,deps);assert.equal(opened,2);await y.close();
  await assert.rejects(startPinnedNativeRelay(f.args,{...deps,startRelay:async()=>{throw Error('uncertain startup');}}));
  await access(f.lock);
  await assert.rejects(startPinnedNativeRelay(f.args,deps));assert.equal(opened,2);
 }finally{await f.cleanup();}
});
