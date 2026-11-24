import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,randomBytes} from 'node:crypto';
import {createSocket} from 'node:dgram';
import {createServer,request} from 'node:http';
import {mkdtemp,mkdir,writeFile,readFile,realpath,rm} from 'node:fs/promises';
import {join,resolve} from 'node:path';
import {tmpdir} from 'node:os';
import {spawn} from 'node:child_process';
import {createInterface} from 'node:readline';
import {validatePrivateCarrierPlan,loadPrivateCarrierPlan} from '../standalone-relay/native-scattering-host.mjs';
const sha=x=>createHash('sha256').update(x).digest('hex');
const binary=process.env.QUANTIC_SCATTERING_NATIVE_TEST;
const cli=resolve('scripts/run-native-scattering-host.mjs');
function plan(){
 return {format:'quantic-private-scattering-host/v1',labOnly:true,pacerBinary:'/tmp/pacer',pacerSha256:'a'.repeat(64),
 listenIP:'127.0.0.1',listenPort:49001,peerIP:'127.0.0.1',peerPort:49003,periodUs:5000,
 carrier:{labOnly:true,role:'client',secretHex:'a'.repeat(64),epochHex:'b'.repeat(64),recvPort:49002,httpPort:49004,queueDir:'/tmp/queue',stateDir:'/tmp/state'}};
}
test('host refuses wildcard/public bind, public target, bad cadence, port conflicts or malformed plan',()=>{
 assert.equal(validatePrivateCarrierPlan(plan()).carrier.role,'client');
 for(const mutate of [
  p=>p.listenIP='0.0.0.0',p=>p.peerIP='8.8.8.8',p=>p.peerIP='192.168.1.2',
  p=>p.periodUs=1,p=>p.listenPort=p.carrier.recvPort,p=>p.pacerSha256='bad',p=>p.extra=true,
  p=>p.carrier.secretHex=p.carrier.epochHex
 ]){const p=plan();mutate(p);assert.throws(()=>validatePrivateCarrierPlan(p));}
});
test('private configuration must match independent pin and restrictive file permissions',{skip:process.platform!=='linux'},async()=>{
 const root=await realpath(await mkdtemp(join(tmpdir(),'qs-carrier-config-')));
 try{
  const path=join(root,'host.json'),data=Buffer.from(JSON.stringify(plan()));
  await writeFile(path,data,{mode:0o600});
  assert.equal((await loadPrivateCarrierPlan(path,sha(data))).listenIP,'127.0.0.1');
  await assert.rejects(loadPrivateCarrierPlan(path,'0'.repeat(64)));
  const loose=join(root,'loose.json');await writeFile(loose,data,{mode:0o644});
  await assert.rejects(loadPrivateCarrierPlan(loose,sha(data)));
 }finally{await rm(root,{recursive:true,force:true});}
});
async function freePort(udp){
 const socket=udp?createSocket('udp4'):createServer();
 return new Promise((res,rej)=>{
  socket.once('error',rej);
  const ready=()=>{const p=socket.address().port;socket.close(()=>res(p));};
  if(udp)socket.bind(0,'127.0.0.1',ready);else socket.listen(0,'127.0.0.1',ready);
 });
}
function launch(file,pin){
 const child=spawn(process.execPath,[cli,file,pin],{stdio:['ignore','pipe','pipe']});
 const closed=new Promise((r,j)=>{child.once('error',j);child.once('close',(code,signal)=>r({code,signal}));});
 const lines=createInterface({input:child.stdout});
 let err='';child.stderr.on('data',b=>{if(err.length<4096)err+=b;});
 const ready=new Promise((r,j)=>{
  const timer=setTimeout(()=>j(Error('host startup timed out')),8000);
  lines.once('line',l=>{clearTimeout(timer);try{r(JSON.parse(l));}catch(e){j(e);}});
  void closed.then(x=>{clearTimeout(timer);j(Error('host exited before readiness: '+x.code+' '+err));},j);
 });
 void ready.catch(()=>{});void closed.catch(()=>{});
 return {child,closed,ready};
}
function post(port,op,payload){
 const raw=Buffer.from(JSON.stringify(payload));
 return new Promise((r,j)=>{
  const q=request({hostname:'127.0.0.1',port,path:'/api/quantic/native/v1/'+op,method:'POST',headers:{'content-type':'application/json','content-length':raw.length,authorization:'Bearer '+'T'.repeat(64)}},res=>{
   const chunks=[];res.on('data',x=>chunks.push(x));res.on('error',j);
   res.on('end',()=>{try{r({status:res.statusCode,body:JSON.parse(Buffer.concat(chunks))});}catch(e){j(e);}});
  });
  q.on('error',j);q.setTimeout(19000,()=>q.destroy(Error('deadline')));q.end(raw);
 });
}
test('two independent supervised host processes carry actual UDP traffic and refuse consumed epoch restart',{skip:process.platform!=='linux'||!binary,timeout:90000},async()=>{
 const root=await realpath(await mkdtemp(join(tmpdir(),'qs-carrier-process-'))),children=[];
 const pacer=await realpath(resolve(binary)),pin=sha(await readFile(pacer));
 const shared={secretHex:randomBytes(32).toString('hex'),epochHex:randomBytes(32).toString('hex')};
 let hits=0;
 const server=createServer(async(req,res)=>{
  const chunks=[];for await(const x of req)chunks.push(x);hits++;
  const raw=Buffer.from(JSON.stringify({received:JSON.parse(Buffer.concat(chunks))}));
  res.writeHead(200,{'content-type':'application/json','content-length':raw.length});res.end(raw);
 });
 try{
  await new Promise(r=>server.listen(0,'127.0.0.1',r));
  const used=new Set([server.address().port]);
  async function alloc(udp){let p;do{p=await freePort(udp);}while(p<1024||used.has(p));used.add(p);return p;}
  const ports=[await alloc(true),await alloc(true)],configs=[];
  for(let i=0;i<2;i++){
   const dir=join(root,'peer-'+i);await mkdir(dir,{mode:0o700});
   const queueDir=join(dir,'queue'),stateDir=join(dir,'state');
   await mkdir(queueDir,{mode:0o700});await mkdir(stateDir,{mode:0o700});
   const p={...plan(),pacerBinary:pacer,pacerSha256:pin,listenPort:ports[i],peerPort:ports[1-i],
    carrier:{labOnly:true,role:i===0?'client':'relay',...shared,queueDir,stateDir,
     recvPort:await alloc(true),httpPort:i===0?await alloc(false):server.address().port}};
   const file=join(dir,'host.json'),data=Buffer.from(JSON.stringify(p));
   await writeFile(file,data,{mode:0o600});configs.push({file,pin:sha(data),p});
  }
  for(const c of configs){const p=launch(c.file,c.pin);children.push(p);const s=await p.ready;assert.equal(s.status,'private-carrier-processes-started');assert.equal(s.remoteTransportVerified,false);assert.ok(!JSON.stringify(s).includes(shared.secretHex));}
  const httpPort=configs[0].p.carrier.httpPort;
  for(const op of ['pull','recover','ack']){
   const payload={operation:op,synthetic:'supervised'};
   assert.deepEqual(await post(httpPort,op,payload),{status:200,body:{received:payload}});
  }
  assert.equal(hits,3);
  for(const child of children)child.child.kill('SIGTERM');
  for(const child of children)assert.equal((await child.closed).code,0);
  const reused=launch(configs[0].file,configs[0].pin);children.push(reused);
  await assert.rejects(reused.ready);
  assert.equal((await reused.closed).code,1);
 }finally{
  for(const {child} of children)if(child.exitCode===null&&child.signalCode===null)child.kill('SIGTERM');
  await Promise.allSettled(children.map(c=>c.closed));
  server.closeAllConnections();await new Promise(r=>server.close(r));await rm(root,{recursive:true,force:true});
 }
});


test('scheduled native host renewal crosses sixteen operations without reusing keys or repeating messages',{skip:process.platform!=='linux'||!binary,timeout:150000},async()=>{
 const root=await realpath(await mkdtemp(join(tmpdir(),'qs-carrier-rollover-'))),children=[];
 const pacer=await realpath(resolve(binary)),pin=sha(await readFile(pacer)),seen=[];
 const server=createServer(async(req,res)=>{
  const chunks=[];for await(const b of req)chunks.push(b);
  const payload=JSON.parse(Buffer.concat(chunks));seen.push(payload.id);
  const raw=Buffer.from(JSON.stringify({received:payload}));
  res.writeHead(200,{'content-type':'application/json','content-length':raw.length});res.end(raw);
 });
 try{
  await new Promise(r=>server.listen(0,'127.0.0.1',r));
  const used=new Set([server.address().port]);
  async function alloc(udp){let p;do{p=await freePort(udp);}while(p<1024||used.has(p));used.add(p);return p;}
  const ports=[await alloc(true),await alloc(true)],recv=[await alloc(true),await alloc(true)],http=await alloc(false);
  const shared=Array.from({length:2},()=>({secretHex:randomBytes(32).toString('hex'),epochHex:randomBytes(32).toString('hex')}));
  const startMs=Date.now()+4000,duration=60000,gap=2000,configs=[];
  for(let i=0;i<2;i++){
   const dir=join(root,'host-'+i),stateDir=join(dir,'state');await mkdir(dir,{mode:0o700});await mkdir(stateDir,{mode:0o700});
   const slots=[];
   for(let k=0;k<2;k++){
    const queueDir=join(dir,'queue-'+k);await mkdir(queueDir,{mode:0o700});
    const p={...plan(),pacerBinary:pacer,pacerSha256:pin,listenPort:ports[i],peerPort:ports[1-i],
     carrier:{labOnly:true,role:i===0?'client':'relay',...shared[k],queueDir,stateDir,recvPort:recv[i],httpPort:i===0?http:server.address().port}};
    const file=join(dir,'epoch-'+k+'.json'),raw=Buffer.from(JSON.stringify(p));
    await writeFile(file,raw,{mode:0o600});
    const at=startMs+k*(duration+gap);slots.push({startMs:at,endMs:at+duration,file,pin:sha(raw)});
   }
   const file=join(dir,'schedule.json'),raw=Buffer.from(JSON.stringify({format:'quantic-private-scattering-schedule/v1',labOnly:true,slots}));
   await writeFile(file,raw,{mode:0o600});configs.push({file,pin:sha(raw),stateDir});
  }
  function launchSchedule(c){
   const child=spawn(process.execPath,[resolve('scripts/run-native-scattering-schedule.mjs'),c.file,c.pin],{stdio:['ignore','pipe','pipe']});
   const output=[],lines=createInterface({input:child.stdout});
   let stderr='';child.stderr.on('data',b=>{if(stderr.length<4096)stderr+=b;});
   lines.on('line',line=>{try{output.push(JSON.parse(line));}catch{output.push({status:'bad-output'});}});
   const closed=new Promise((r,j)=>{child.once('error',j);child.once('close',(code,signal)=>r({code,signal}));});
   void closed.catch(()=>{});
   return {child,closed,output,get stderr(){return stderr;}};
  }
  for(const c of configs)children.push(launchSchedule(c));
  async function awaitSlot(n,deadline){
   while(Date.now()<deadline){
    for(const c of children)assert.equal(c.child.exitCode,null,c.stderr);
    if(children.every(c=>c.output.some(x=>x.status==='scheduled-private-carrier-active'&&x.slot===n)))return;
    await new Promise(r=>setTimeout(r,100));
   }
   throw Error('scheduled slot did not start: '+n);
  }
  await awaitSlot(1,startMs+8000);
  for(let i=0;i<16;i++){
   const payload={id:i,synthetic:'rollover'};
   assert.deepEqual(await post(http,'pull',payload),{status:200,body:{received:payload}});
  }
  assert.equal((await post(http,'pull',{id:16})).status,503);
  assert.equal(seen.length,16);
  await awaitSlot(2,startMs+duration+gap+8000);
  for(let i=16;i<20;i++){
   const payload={id:i,synthetic:'rollover'};
   assert.deepEqual(await post(http,'pull',payload),{status:200,body:{received:payload}});
  }
  assert.deepEqual(seen,Array.from({length:20},(_,i)=>i));
  for(const c of children)c.child.kill('SIGTERM');
  for(const c of children)assert.equal((await c.closed).code,0,c.stderr);
  // Each host must have durably consumed BOTH distinct epochs.
  const {readdir}=await import('node:fs/promises');
  for(const c of configs)assert.equal((await readdir(c.stateDir)).filter(x=>x.startsWith('used-')).length,2);
 }finally{
  for(const c of children)if(c.child.exitCode===null&&c.child.signalCode===null)c.child.kill('SIGTERM');
  await Promise.allSettled(children.map(c=>c.closed));
  server.closeAllConnections();await new Promise(r=>server.close(r));await rm(root,{recursive:true,force:true});
 }
});
