import test from 'node:test';
import assert from 'node:assert/strict';
import {createServer,request} from 'node:http';
import {OVERLAP_POLICY as P,validateOverlapSchedule,runOverlapSchedule,startStableMailboxGateway} from '../standalone-relay/native-scattering-overlap.mjs';
const BASE=1700000000000;
function fixture(){
 const plans=Array.from({length:3},(_,i)=>({
  format:'quantic-private-scattering-host/v1',labOnly:true,pacerBinary:'/tmp/pacer',pacerSha256:'a'.repeat(64),
  listenIP:'127.0.0.1',listenPort:49100+i,peerIP:'127.0.0.1',peerPort:49200+i,periodUs:5000,
  carrier:{labOnly:true,role:'client',secretHex:String(i+1).repeat(64),epochHex:String(i+4).repeat(64),recvPort:49300+i,httpPort:49400+i,queueDir:'/tmp/queue-'+i,stateDir:'/tmp/state'}
 }));
 const slots=plans.map((_,i)=>{const startMs=BASE+1000+i*(P.minSlotMs-P.overlapMs);
  return {startMs,endMs:startMs+P.minSlotMs,file:'/tmp/slot-'+i+'.json',pin:'b'.repeat(64)};});
 return {spec:{format:'quantic-private-scattering-overlap/v1',labOnly:true,gatewayPort:49500,slots},plans};
}
test('overlap schedule rejects port collisions, repeated keys, changed peers and insufficient drain',()=>{
 const f=fixture();assert.equal(validateOverlapSchedule(f.spec,f.plans,{now:BASE}),true);
 for(const alter of [
  f=>f.spec.gatewayPort=f.plans[1].carrier.httpPort,
  f=>f.plans[1].listenPort=f.plans[0].carrier.recvPort,
  f=>f.plans[1].peerPort=f.plans[0].peerPort,
  f=>f.plans[1].carrier.secretHex=f.plans[0].carrier.epochHex,
  f=>f.plans[1].carrier.queueDir=f.plans[0].carrier.queueDir,
  f=>f.plans[1].peerIP='127.0.0.2',
  f=>f.spec.slots[1].startMs++,
  f=>f.spec.slots[0].endMs-=1000
 ]){const x=fixture();alter(x);assert.throws(()=>validateOverlapSchedule(x.spec,x.plans,{now:BASE}));}
});
test('prewarm before cutover, keep previous lane during drain and only select authenticated peers',async()=>{
 for(const fail of [false,true]){
  const f=fixture();let now=BASE,select,active=0,maxActive=0,closed=0;
  const events=[];
  const run=runOverlapSchedule(f,{
   now:()=>now,monotonic:()=>now-BASE,pause:async ms=>{now+=ms;},
   startGateway:async opts=>{select=opts.select;return {close:async()=>{}};},
   startHost:async(p)=>{
    const i=active+closed;active++;maxActive=Math.max(maxActive,active);
    events.push({event:'start',i,now,oldPort:select()?.httpPort});
    let done;const promise=new Promise(r=>{done=r;});
    return {httpPort:p.carrier.httpPort,role:'client',authenticatedPeerSeen:()=>!(fail&&i===1),closed:promise,
     close:async()=>{active--;closed++;events.push({event:'close',i,now});done({failed:false});}};
   },
   onSlot:s=>events.push({event:'select',i:s.slot-1,now,port:select().httpPort})
  });
  if(fail){await assert.rejects(run);assert.equal(closed,2);assert.equal(events.filter(x=>x.event==='select').length,1);}
  else{
   const r=await run;assert.equal(r.completedSlots,3);assert.equal(maxActive,2);
   assert.equal(events.find(x=>x.event==='start'&&x.i===1).oldPort,49400);
   const sw=events.find(x=>x.event==='select'&&x.i===1),old=events.find(x=>x.event==='close'&&x.i===0);
   assert.equal(old.now-sw.now,P.drainMs);
  }
  assert.equal(active,0);
 }
});
async function listen(server){
 await new Promise(r=>server.listen(0,'127.0.0.1',r));return server.address().port;
}
async function close(server){server.closeAllConnections();await new Promise(r=>server.close(r));}
function post(port,id){
 const data=Buffer.from(JSON.stringify({id}));
 return new Promise((r,j)=>{
  const q=request({hostname:'127.0.0.1',port,path:'/api/quantic/native/v1/pull',method:'POST',headers:{'content-type':'application/json','content-length':data.length,authorization:'Bearer '+'T'.repeat(64)}},res=>{
   const parts=[];res.on('data',b=>parts.push(b));res.on('end',()=>r({status:res.statusCode,body:JSON.parse(Buffer.concat(parts))}));res.on('error',j);
  });q.on('error',j);q.end(data);
 });
}
test('stable loopback gateway captures lane exactly once; no cross-epoch retry on uncertain response',async()=>{
 const hits=[];let selected,entered,release;
 const enteredFirst=new Promise(r=>{entered=r;}),releaseFirst=new Promise(r=>{release=r;});
 function backend(lane){return createServer(async(req,res)=>{
  const chunks=[];for await(const b of req)chunks.push(b);
  const data=JSON.parse(Buffer.concat(chunks));hits.push([lane,data.id]);
  if(data.id===1){entered();await releaseFirst;}
  if(data.id===3){req.socket.destroy();return;}
  const body=Buffer.from(JSON.stringify({lane,id:data.id}));
  res.writeHead(200,{'content-length':body.length,'content-type':'application/json'});res.end(body);
 });}
 const a=backend('a'),b=backend('b'),reservation=createServer();
 const pa=await listen(a),pb=await listen(b),pg=await listen(reservation);await close(reservation);
 let gate;
 try{
  selected={httpPort:pa};gate=await startStableMailboxGateway({port:pg,select:()=>selected});
  const first=post(pg,1);await enteredFirst;selected={httpPort:pb};release();
  assert.deepEqual(await first,{status:200,body:{lane:'a',id:1}});
  assert.deepEqual(await post(pg,2),{status:200,body:{lane:'b',id:2}});
  assert.equal((await post(pg,3)).status,502);
  selected={httpPort:pa};assert.deepEqual(hits,[['a',1],['b',2],['b',3]]);
  selected=null;assert.equal((await post(pg,4)).status,503);assert.equal(hits.length,3);
 }finally{release();await gate?.close();await close(a);await close(b);}
});
