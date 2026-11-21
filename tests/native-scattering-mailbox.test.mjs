import test from 'node:test';
import assert from 'node:assert/strict';
import {createServer,request} from 'node:http';
import {createSocket} from 'node:dgram';
import {spawn} from 'node:child_process';
import {randomBytes} from 'node:crypto';
import {mkdtemp,mkdir,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {startScatteringMailboxEndpoint} from '../standalone-relay/native-scattering-mailbox.mjs';
const binary=process.env.QUANTIC_SCATTERING_NATIVE_TEST;
const token='synthetic-'+'a'.repeat(48),base='/api/quantic/native/v1/';
async function freeUDP(){const s=createSocket('udp4');await new Promise(r=>s.bind(0,'127.0.0.1',r));const p=s.address().port;await new Promise(r=>s.close(r));return p;}
function post(port,path,body){
 return new Promise((resolve,reject)=>{const b=Buffer.from(JSON.stringify(body));const q=request({hostname:'127.0.0.1',port,path,method:'POST',headers:{'content-type':'application/json','content-length':b.length,authorization:'Bearer '+token}},res=>{const parts=[];res.on('data',x=>parts.push(x));res.on('end',()=>resolve({status:res.statusCode,body:JSON.parse(Buffer.concat(parts))}));res.on('error',reject);});q.on('error',reject);q.setTimeout(19000,()=>q.destroy(Error('deadline')));q.end(b);});
}
test('native Scattering pacers and sinks carry bounded mailbox HTTP operations over real UDP without public HTTP',{skip:!binary,timeout:45000},async()=>{
 const dir=await mkdtemp(join(tmpdir(),'qs-mailbox-')),kids=[],endpoints=[],hits=[];
 const server=createServer(async(req,res)=>{const parts=[];for await(const c of req)parts.push(c);hits.push({path:req.url,token:req.headers.authorization,body:JSON.parse(Buffer.concat(parts))});const b=Buffer.from(JSON.stringify({op:req.url.slice(base.length),ok:true}));res.writeHead(req.url===base+'send'?202:200,{'Content-Type':'application/json','Content-Length':b.length});res.end(b);});
 try{
  await new Promise(r=>server.listen(0,'127.0.0.1',r));
  const shared={labOnly:true,secretHex:randomBytes(32).toString('hex'),epochHex:randomBytes(32).toString('hex'),recvPort:0};
  let config;
  for(const role of ['client','relay']){
   const queueDir=join(dir,role+'-queue'),stateDir=join(dir,role+'-state');await mkdir(queueDir,{mode:0o700});await mkdir(stateDir,{mode:0o700});
   const c={...shared,role,queueDir,stateDir,httpPort:role==='client'?0:server.address().port};
   endpoints.push(await startScatteringMailboxEndpoint(c));if(role==='client')config=c;
  }
  const ports=[await freeUDP(),await freeUDP()];assert.notEqual(ports[0],ports[1]);
  function launch(args){const p=spawn(binary,args,{stdio:'ignore'});kids.push(p);return p;}
  for(let i=0;i<2;i++){
   launch(['-mode','sink','-listen','127.0.0.1:'+ports[i],'-forward','127.0.0.1:'+endpoints[i].recvPort]);
   launch(['-target','127.0.0.1:'+ports[1-i],'-queue-dir',join(dir,(i===0?'client':'relay')+'-queue'),'-period-us','5000','-poll','10ms','-wait-mode','native']);
  }
  await new Promise(r=>setTimeout(r,400));assert.ok(kids.every(p=>p.exitCode===null));
  assert.equal((await post(endpoints[0].httpPort,'/not-a-mailbox-route',{})).status,400);assert.equal(hits.length,0);
  for(const op of ['send','pull','ack','recover']){
   const payload={fixture:op,...(op==='send'?{syntheticCiphertext:'x'.repeat(8192)}:{})};
   const result=await post(endpoints[0].httpPort,base+op,payload);
   assert.deepEqual(result,{status:op==='send'?202:200,body:{op,ok:true}});assert.deepEqual(hits.at(-1),{path:base+op,token:'Bearer '+token,body:payload});
  }
  assert.equal(hits.length,4);endpoints[0].close();
  const fresh=join(dir,'fresh');await mkdir(fresh,{mode:0o700});
  await assert.rejects(startScatteringMailboxEndpoint({...config,queueDir:fresh}));
 }finally{
  for(const e of endpoints)e.close();for(const p of kids)p.kill();
  await Promise.all(kids.map(p=>p.exitCode!==null?Promise.resolve():new Promise(r=>{p.once('exit',r);p.once('error',r);})));
  server.closeAllConnections();await new Promise(r=>server.close(r));await rm(dir,{recursive:true,force:true});
 }
});
