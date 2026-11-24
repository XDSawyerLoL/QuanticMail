import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,randomBytes} from 'node:crypto';
import {createSocket} from 'node:dgram';
import {createServer,request} from 'node:http';
import {mkdtemp,mkdir,writeFile,readFile,realpath,rm} from 'node:fs/promises';
import {join,resolve,dirname} from 'node:path';
import {tmpdir} from 'node:os';
import {spawn,execFileSync} from 'node:child_process';
import {createInterface} from 'node:readline';
const sha=x=>createHash('sha256').update(x).digest('hex');
const binary=process.env.QUANTIC_SCATTERING_NATIVE_TEST;
const vault=process.env.QUANTIC_WINDOWS_VAULT_TEST;
const packageRoot=binary?dirname(dirname(resolve(binary))):'';
function plan(){
 return {format:'quantic-private-scattering-host/v1',labOnly:true,pacerBinary:'/tmp/pacer',pacerSha256:'a'.repeat(64),
 listenIP:'127.0.0.1',listenPort:49001,peerIP:'127.0.0.1',peerPort:49003,periodUs:5000,
 carrier:{labOnly:true,role:'client',secretHex:'a'.repeat(64),epochHex:'b'.repeat(64),recvPort:49002,httpPort:49004,queueDir:'/tmp/queue',stateDir:'/tmp/state'}};
}
async function freePort(udp){
 const socket=udp?createSocket('udp4'):createServer();
 return new Promise((res,rej)=>{
  socket.once('error',rej);
  const ready=()=>{const p=socket.address().port;socket.close(()=>res(p));};
  if(udp)socket.bind(0,'127.0.0.1',ready);else socket.listen(0,'127.0.0.1',ready);
 });
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
test('Windows packaged overlap schedule uses native shared epoch ledger and stable ingress',{skip:process.platform!=='win32'||!binary||!vault,timeout:180000},async()=>{
 const root=await realpath(await mkdtemp(join(process.env.QUANTIC_WINDOWS_TEST_ROOT??tmpdir(),'qs-overlap-'))),children=[];
 const pacer=resolve(binary),pin=sha(await readFile(pacer)),vaultPin=sha(await readFile(vault)),seen=[];
 function native(op,dir,input){execFileSync(vault,[op,dir],{input,windowsHide:true,timeout:15000});}
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
  const ports=[[await alloc(true),await alloc(true)],[await alloc(true),await alloc(true)]],recv=[[await alloc(true),await alloc(true)],[await alloc(true),await alloc(true)]],http=await alloc(false),lanes=[await alloc(false),await alloc(false)];
  const shared=Array.from({length:2},()=>({secretHex:randomBytes(32).toString('hex'),epochHex:randomBytes(32).toString('hex')}));
  const startMs=Date.now()+12000,duration=85000,gap=-40000,configs=[];
  for(let i=0;i<2;i++){
   const dir=join(root,'host-'+i),stateDir=join(dir,'state');native('--windows-scattering-create-lab',dir);
   const slots=[];
   for(let k=0;k<2;k++){
    const lane=join(dir,'lane-'+k),queueDir=join(lane,'queue');native('--windows-scattering-create-lab',lane);
    const p={...plan(),pacerBinary:pacer,pacerSha256:pin,listenPort:ports[i][k],peerPort:ports[1-i][k],
     carrier:{labOnly:true,role:i===0?'client':'relay',...shared[k],queueDir,stateDir,recvPort:recv[i][k],httpPort:i===0?lanes[k]:server.address().port}};
    const file=join(lane,'scattering.json'),raw=Buffer.from(JSON.stringify(p));
    native('--windows-scattering-config-lab',lane,raw);
    const at=startMs+k*(duration+gap);slots.push({startMs:at,endMs:at+duration,file,pin:sha(raw)});
   }
   const raw=Buffer.from(JSON.stringify({format:'quantic-private-scattering-overlap/v1',labOnly:true,gatewayPort:i===0?http:null,slots}));
   native('--windows-scattering-config-lab',dir,raw);configs.push({dir,pin:sha(raw),stateDir});
  }
  function launchSchedule(c){
   const child=spawn(process.execPath,[join(packageRoot,'scripts','run-windows-scattering-overlap.mjs'),resolve(vault),vaultPin,pin,c.dir,c.pin],{stdio:['pipe','pipe','pipe'],windowsHide:true});
   child.stdin.on('error',()=>{});
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
  await awaitSlot(1,startMs+12000);
  for(let i=0;i<4;i++){
   const payload={id:i,synthetic:'rollover'};
   assert.deepEqual(await post(http,'pull',payload),{status:200,body:{received:payload}});
  }
  assert.equal(seen.length,4);
  // Next carrier is alive in prewarm, but gateway still uses old carrier.
  const switchAt=startMs+duration+gap+5000;
  while(Date.now()<switchAt-2500)await new Promise(r=>setTimeout(r,50));
  const payload={id:4,synthetic:'prewarm'};
  assert.deepEqual(await post(http,'pull',payload),{status:200,body:{received:payload}});
  await awaitSlot(2,switchAt+5000);
  for(let i=5;i<9;i++){
   const payload={id:i,synthetic:'rollover'};
   assert.deepEqual(await post(http,'pull',payload),{status:200,body:{received:payload}});
  }
  assert.deepEqual(seen,Array.from({length:9},(_,i)=>i));
  assert.ok(Date.now()<startMs+duration,'old lane still in drain');
  assert.ok(children.every(c=>c.output.filter(x=>x.status==='scheduled-private-carrier-active').every(x=>x.authenticatedCellsObserved===true)));
  for(const c of children)c.child.stdin.end('STOP\n');
  for(const c of children)assert.equal((await c.closed).code,0,c.stderr);
  // Each host must have durably consumed BOTH distinct epochs.
  const {readdir}=await import('node:fs/promises');
  for(const c of configs)assert.equal((await readdir(c.stateDir)).filter(x=>x.startsWith('used-')).length,2);
  // Attempt a fresh lane using a consumed epoch. The guard must refuse
  // before starting any network child. The shared marker survives process exit.
  const c=configs[0],lane=join(c.dir,'lane-reuse');native('--windows-scattering-create-lab',lane);
  assert.throws(()=>execFileSync(vault,['--windows-scattering-overlap-guard-lab',c.dir,lane],{input:shared[0].epochHex,windowsHide:true,timeout:15000}));
 }finally{
  for(const c of children)if(c.child.exitCode===null&&c.child.signalCode===null){c.child.stdin.end();const timer=setTimeout(()=>c.child.kill(),10000);void c.closed.finally(()=>clearTimeout(timer));}
  await Promise.allSettled(children.map(c=>c.closed));
  server.closeAllConnections();await new Promise(r=>server.close(r));await rm(root,{recursive:true,force:true});
 }
});
