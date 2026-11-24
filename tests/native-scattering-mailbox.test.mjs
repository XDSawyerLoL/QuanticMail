import {startManagedCarrier,startNegotiatedManagedCarrier,validateManagedCarrier} from '../desktop/native-managed-scattering.mjs';
import test from 'node:test';
import assert from 'node:assert/strict';
import {createServer,request} from 'node:http';
import {createSocket} from 'node:dgram';
import {spawn,execFileSync} from 'node:child_process';
import {randomBytes,createHash,generateKeyPairSync} from 'node:crypto';
import {mkdtemp,mkdir,rm,readFile,realpath} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
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
  const ports=[await freeUDP(),await freeUDP()];assert.notEqual(ports[0],ports[1]);
  for(const role of ['client','relay']){
   const scope=join(dir,role);
   const queueDir=windows?join(scope,'queue'):join(dir,role+'-queue'),stateDir=windows?join(scope,'state'):join(dir,role+'-state');
   let opts={};if(windows){execFileSync(vault,['--windows-scattering-create-lab',scope]);opts={windowsBootstrap:{binary:vault,binarySha256:createHash('sha256').update(await readFile(vault)).digest('hex'),dir:scope}};}else{await mkdir(queueDir,{mode:0o700});await mkdir(stateDir,{mode:0o700});}
   queues.push(queueDir);
   const c={...shared,role,queueDir,stateDir,httpPort:role==='client'?0:server.address().port};
   if(role==='client'){
    config=c;bootstrap=opts;endpoints.push(await startManagedCarrier({binary,binaryPin:createHash('sha256').update(await readFile(binary)).digest('hex'),config:c,listen:'127.0.0.1:'+ports[0],target:'127.0.0.1:'+ports[1],...opts}));
   }else endpoints.push(await startScatteringMailboxEndpoint(c,opts));
  }
  function launch(args){const p=spawn(binary,args,{stdio:'ignore'});kids.push(p);return p;}
  for(let i=1;i<2;i++){
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
  for(const e of endpoints)await e.close();for(const p of kids)p.kill();
  await Promise.all(kids.map(p=>p.exitCode!==null?Promise.resolve():new Promise(r=>{p.once('exit',r);p.once('error',r);})));
  server.closeAllConnections();await new Promise(r=>server.close(r));await rm(dir,{recursive:true,force:true,maxRetries:10,retryDelay:200});
 }
});

test('managed profile rejects changes, foreign paths and wrong loopback port',()=>{
 const c={labOnly:true,role:'client',secretHex:'a'.repeat(64),epochHex:'b'.repeat(64),recvPort:49001,httpPort:49002,queueDir:'private/queue',stateDir:'private/state'};
 const raw=Buffer.from(JSON.stringify(c)),p={configPin:createHash('sha256').update(raw).digest('hex'),listen:'127.0.0.1:49003',target:'127.0.0.1:49004'},scope={endpoint:'http://127.0.0.1:49002/'},paths={queueDir:c.queueDir,stateDir:c.stateDir};
 assert.deepEqual(validateManagedCarrier(p,raw,scope,paths),c);
 assert.throws(()=>validateManagedCarrier({...p,configPin:'f'.repeat(64)},raw,scope,paths));
 assert.throws(()=>validateManagedCarrier({...p,target:'0.0.0.0:1234'},raw,scope,paths));
 assert.throws(()=>validateManagedCarrier(p,raw,{endpoint:'http://127.0.0.1:49009/'},paths));
 assert.throws(()=>validateManagedCarrier(p,raw,scope,{...paths,queueDir:'foreign'}));
});

test('negotiated managed carriers activate native UDP on both endpoints without pre-shared keys',{skip:!binary||(windows&&!vault),timeout:90000},async()=>{
 const root=await realpath(await mkdtemp(join(windows?(process.env.QUANTIC_WINDOWS_TEST_ROOT??await realpath(tmpdir())):tmpdir(),'qs-negotiated-')));
 const sockets=[],carriers=[],hits=[];
 const server=createServer(async(req,res)=>{
  const chunks=[];for await(const c of req)chunks.push(c);
  hits.push({path:req.url,body:JSON.parse(Buffer.concat(chunks)),token:req.headers.authorization});
  const data=Buffer.from(JSON.stringify({ok:true}));res.writeHead(202,{'Content-Type':'application/json','Content-Length':data.length});res.end(data);
 });
 const identity=()=>{const a=generateKeyPairSync('ec',{namedCurve:'prime256v1'}),b=generateKeyPairSync('ml-dsa-65');return {local:{classical:a.publicKey,pq:b.publicKey},privateKeys:{classical:a.privateKey,pq:b.privateKey}};};
 try{
  await new Promise((r,j)=>{server.once('error',j);server.listen(0,'127.0.0.1',r);});
  const ids=[identity(),identity()],configs=[],boots=[];
  for(let i=0;i<2;i++){
   const role=i?'relay':'client',scope=join(root,role);
   const queueDir=join(scope,'queue'),stateDir=join(scope,'state');
   if(windows){execFileSync(vault,['--windows-scattering-create-lab',scope]);boots.push({binary:vault,binarySha256:createHash('sha256').update(await readFile(vault)).digest('hex'),dir:scope});}
   else{await mkdir(scope,{mode:0o700});await mkdir(queueDir,{mode:0o700});await mkdir(stateDir,{mode:0o700});boots.push(undefined);}
   configs.push({labOnly:true,role,queueDir,stateDir,recvPort:0,httpPort:i?server.address().port:0});
   const s=createSocket('udp4');sockets.push(s);await new Promise((r,j)=>{s.once('error',j);s.bind(0,'127.0.0.1',r);});
  }
  const bootstrapPorts=sockets.map(s=>s.address().port);
  for(let i=0;i<2;i++)await new Promise((r,j)=>{sockets[i].once('error',j);sockets[i].connect(bootstrapPorts[1-i],'127.0.0.1',r);});
  const ports=[await freeUDP(),await freeUDP()];assert.notEqual(ports[0],ports[1]);
  const binaryPin=createHash('sha256').update(await readFile(binary)).digest('hex'),context={channel:randomBytes(48).toString('hex'),generation:0,previous:'0'.repeat(96)};
  const options=i=>({binary,binaryPin,config:configs[i],listen:'127.0.0.1:'+ports[i],target:'127.0.0.1:'+ports[1-i],windowsBootstrap:boots[i],socket:sockets[i],...ids[i],peer:ids[1-i].local,context});
  await assert.rejects(startNegotiatedManagedCarrier({...options(0),config:{...configs[0],secretHex:'a'.repeat(64)}}));
  const outcomes=await Promise.allSettled([startNegotiatedManagedCarrier(options(0)),startNegotiatedManagedCarrier(options(1))]);
  for(const o of outcomes)if(o.status==='fulfilled')carriers.push(o.value);
  for(const o of outcomes)if(o.status==='rejected')throw o.reason;
  const client=outcomes[0].value;
  assert.equal(Object.hasOwn(client,'secretHex'),false);assert.equal(Object.hasOwn(client,'epochHex'),false);
  const body={synthetic:'negotiated managed UDP'};
  assert.deepEqual(await post(client.httpPort,base+'send',body),{status:202,body:{ok:true}});
  assert.deepEqual(hits,[{path:base+'send',body,token:'Bearer '+token}]);
  await client.close();await assert.rejects(post(client.httpPort,base+'send',body));assert.equal(hits.length,1);
  console.log('NEGOTIATED_MANAGED_CARRIER_EVIDENCE '+JSON.stringify({platform:process.platform,negotiated:true,nativePacer:true,preSharedSecret:false,localEpochGuard:true,syntheticMailbox:true,physicalHosts:1,releaseAuthorized:false}));
 }finally{
  await Promise.allSettled(carriers.map(c=>c.close()));
  for(const s of sockets)await new Promise(r=>{try{s.close(r);}catch{r();}});
  server.closeAllConnections();await new Promise(r=>server.close(r));
  await rm(root,{recursive:true,force:true,maxRetries:10,retryDelay:200});
 }
});
