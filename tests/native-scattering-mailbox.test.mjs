import test from 'node:test';
import assert from 'node:assert/strict';
import {createServer,request} from 'node:http';
import {createSocket} from 'node:dgram';
import {spawn,execFileSync} from 'node:child_process';
import {randomBytes,createHash} from 'node:crypto';
import {mkdtemp,mkdir,rm,readFile,realpath} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {startDirectRenewalCarrier} from '../desktop/native-direct-renewal-carrier.mjs';
import {startScatteringMailboxEndpoint} from '../standalone-relay/native-scattering-mailbox.mjs';
const binary=process.env.QUANTIC_SCATTERING_NATIVE_TEST?resolve(process.env.QUANTIC_SCATTERING_NATIVE_TEST):undefined;
const windows=process.platform==='win32',vault=process.env.QUANTIC_WINDOWS_VAULT_TEST?resolve(process.env.QUANTIC_WINDOWS_VAULT_TEST):undefined;
const token='synthetic-'+'a'.repeat(48),base='/api/quantic/native/v1/';
async function freeUDP(){const s=createSocket('udp4');await new Promise(r=>s.bind(0,'127.0.0.1',r));const p=s.address().port;await new Promise(r=>s.close(r));return p;}
function post(port,path,body){
 return new Promise((resolve,reject)=>{const b=Buffer.from(JSON.stringify(body));const q=request({hostname:'127.0.0.1',port,path,method:'POST',headers:{'content-type':'application/json','content-length':b.length,authorization:'Bearer '+token}},res=>{const parts=[];res.on('data',x=>parts.push(x));res.on('end',()=>resolve({status:res.statusCode,body:JSON.parse(Buffer.concat(parts))}));res.on('error',reject);});q.on('error',reject);q.setTimeout(19000,()=>q.destroy(Error('deadline')));q.end(b);});
}
test('native Scattering pacers and sinks carry bounded mailbox HTTP operations over real UDP without public HTTP',{skip:!binary||(windows&&!vault),timeout:90000},async()=>{
 const parent=windows?(process.env.QUANTIC_WINDOWS_TEST_ROOT??await realpath(tmpdir())):tmpdir();
 const dir=await realpath(await mkdtemp(join(parent,'qs-mailbox-'))),kids=[],endpoints=[],hits=[];
 const server=createServer(async(req,res)=>{const parts=[];for await(const c of req)parts.push(c);hits.push({path:req.url,token:req.headers.authorization,body:JSON.parse(Buffer.concat(parts))});const b=Buffer.from(JSON.stringify({op:req.url.slice(base.length),ok:true}));res.writeHead(req.url===base+'send'?202:200,{'Content-Type':'application/json','Content-Length':b.length});res.end(b);});
 try{
  await new Promise(r=>server.listen(0,'127.0.0.1',r));
  const shared={labOnly:true,secretHex:randomBytes(32).toString('hex'),epochHex:randomBytes(32).toString('hex'),recvPort:0};
  let config,bootstrap;const queues=[];
  for(const role of ['client','relay']){
   const scope=join(dir,role);
   const queueDir=windows?join(scope,'queue'):join(dir,role+'-queue'),stateDir=windows?join(scope,'state'):join(dir,role+'-state');
   let opts={};if(windows){execFileSync(vault,['--windows-scattering-create-lab',scope]);opts={windowsBootstrap:{binary:vault,binarySha256:createHash('sha256').update(await readFile(vault)).digest('hex'),dir:scope}};}else{await mkdir(queueDir,{mode:0o700});await mkdir(stateDir,{mode:0o700});}
   queues.push(queueDir);
   const c={...shared,role,queueDir,stateDir,httpPort:role==='client'?0:server.address().port};
   endpoints.push(await startScatteringMailboxEndpoint(c,opts));if(role==='client'){config=c;bootstrap=opts;}
  }
  const ports=[await freeUDP(),await freeUDP()];assert.notEqual(ports[0],ports[1]);
  function launch(args){const p=spawn(binary,args,{stdio:'ignore'});kids.push(p);return p;}
  for(let i=0;i<2;i++){
   launch(['-mode','sink','-listen','127.0.0.1:'+ports[i],'-forward','127.0.0.1:'+endpoints[i].recvPort]);
   launch(['-target','127.0.0.1:'+ports[1-i],'-queue-dir',queues[i],'-period-us','5000','-poll','10ms','-wait-mode','native']);
  }
  await new Promise(r=>setTimeout(r,400));assert.ok(kids.every(p=>p.exitCode===null));
  assert.equal((await post(endpoints[0].httpPort,'/not-a-mailbox-route',{})).status,400);assert.equal(hits.length,0);
  for(let i=0;i<16;i++){
   const op=['send','pull','ack','recover'][i%4];
   const payload={fixture:op,sequence:i,...(i===0?{syntheticCiphertext:'x'.repeat(8192)}:{})};
   const result=await post(endpoints[0].httpPort,base+op,payload);
   assert.deepEqual(result,{status:op==='send'?202:200,body:{op,ok:true}});assert.deepEqual(hits.at(-1),{path:base+op,token:'Bearer '+token,body:payload});
  }
  assert.equal(hits.length,16);
  assert.equal((await post(endpoints[0].httpPort,base+'pull',{})).status,503);
  assert.equal(hits.length,16);
  if(windows){await assert.rejects(startScatteringMailboxEndpoint({...config,epochHex:randomBytes(32).toString('hex')},bootstrap));endpoints[0].close();}
  else{endpoints[0].close();const fresh=join(dir,'fresh');await mkdir(fresh,{mode:0o700});await assert.rejects(startScatteringMailboxEndpoint({...config,queueDir:fresh}));}
 }finally{
  for(const e of endpoints)e.close();for(const p of kids)p.kill();
  await Promise.all(kids.map(p=>p.exitCode!==null?Promise.resolve():new Promise(r=>{p.once('exit',r);p.once('error',r);})));
  server.closeAllConnections();await new Promise(r=>server.close(r));await rm(dir,{recursive:true,force:true,maxRetries:10,retryDelay:200});
 }
});

test('renewal adapter retires uncertain epoch, never repeats native exchange',async()=>{
 let requests=0,closes=0;
 const carrier=await startDirectRenewalCarrier({carrier:{role:'client'}},{startHost:async()=>({
  authenticatedPeerSeen:()=>true,requestRenewal:async()=>{requests++;return {status:502,body:Buffer.from('uncertain')};},
  close:async()=>{closes++;}
 })});
 await assert.rejects(carrier.exchange(Buffer.alloc(8193)));
 assert.equal(requests,0);
 await assert.rejects(carrier.exchange(Buffer.from('synthetic request')),/not confirmed/);
 await assert.rejects(carrier.exchange(Buffer.from('another request')));
 assert.equal(requests,1);assert.equal(closes,1);
});
test('native renewal lane transfers bounded synthetic request and proof over real UDP without HTTP',{skip:!binary||(windows&&!vault),timeout:90000},async()=>{
 const parent=windows?(process.env.QUANTIC_WINDOWS_TEST_ROOT??await realpath(tmpdir())):tmpdir();
 const dir=await realpath(await mkdtemp(join(parent,'qs-renewal-'))),kids=[],endpoints=[],queues=[];
 const requestBytes=randomBytes(8192),proofBytes=randomBytes(8192);
 let hits=0;
 try{
  const shared={labOnly:true,secretHex:randomBytes(32).toString('hex'),epochHex:randomBytes(32).toString('hex'),recvPort:0};
  for(const role of ['client','relay']){
   const scope=join(dir,role),queueDir=windows?join(scope,'queue'):join(dir,role+'-queue'),stateDir=windows?join(scope,'state'):join(dir,role+'-state');
   let opts={};if(windows){execFileSync(vault,['--windows-scattering-create-lab',scope]);opts={windowsBootstrap:{binary:vault,binarySha256:createHash('sha256').update(await readFile(vault)).digest('hex'),dir:scope}};}else{await mkdir(queueDir,{mode:0o700});await mkdir(stateDir,{mode:0o700});}
   queues.push(queueDir);
   const c={...shared,role,queueDir,stateDir,httpPort:role==='client'?0:1};
   endpoints.push(await startScatteringMailboxEndpoint(c,{...opts,profile:'direct-renewal',...(role==='relay'?{directRenew:async raw=>{
    hits++;assert.deepEqual(raw,requestBytes);return {status:200,body:proofBytes};
   }}:{})}));
  }
  assert.equal(endpoints[0].httpPort,undefined);assert.equal(endpoints[1].httpPort,undefined);
  assert.equal(typeof endpoints[1].requestRenewal,'undefined');
  await assert.rejects(endpoints[0].requestRenewal(Buffer.alloc(8193)));
  assert.equal(hits,0);
  const ports=[await freeUDP(),await freeUDP()];assert.notEqual(ports[0],ports[1]);
  for(let i=0;i<2;i++){
   kids.push(spawn(binary,['-mode','sink','-listen','127.0.0.1:'+ports[i],'-forward','127.0.0.1:'+endpoints[i].recvPort],{stdio:'ignore'}));
   kids.push(spawn(binary,['-target','127.0.0.1:'+ports[1-i],'-queue-dir',queues[i],'-period-us','5000','-poll','10ms','-wait-mode','native'],{stdio:'ignore'}));
  }
  await new Promise(r=>setTimeout(r,400));assert.ok(kids.every(p=>p.exitCode===null));
  const result=await endpoints[0].requestRenewal(requestBytes);
  assert.equal(result.status,200);assert.deepEqual(result.body,proofBytes);assert.equal(hits,1);
 }finally{
  for(const e of endpoints)e.close();for(const p of kids)p.kill();
  await Promise.all(kids.map(p=>p.exitCode!==null||p.signalCode!==null?Promise.resolve():new Promise(r=>{p.once('exit',r);p.once('error',r);})));
  await Promise.all(endpoints.map(e=>e.closed));
  await rm(dir,{recursive:true,force:true,maxRetries:10,retryDelay:200});
 }
});
