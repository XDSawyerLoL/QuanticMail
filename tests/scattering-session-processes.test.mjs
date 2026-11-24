import test from 'node:test';
import assert from 'node:assert/strict';
import {fork} from 'node:child_process';
import {randomBytes,generateKeyPairSync} from 'node:crypto';
import {fileURLToPath} from 'node:url';
const helper=fileURLToPath(new URL('./helpers/native-session-peer.mjs',import.meta.url));
function worker(){
 const child=fork(helper,[],{stdio:['ignore','ignore','ignore','ipc'],execArgv:[]});
 let readyResolve,readyReject,resultResolve,resultReject;
 const ready=new Promise((r,j)=>{readyResolve=r;readyReject=j;});
 const result=new Promise((r,j)=>{resultResolve=r;resultReject=j;});
 // Both promises may reject during launch; attach handlers immediately.
 ready.catch(()=>{});result.catch(()=>{});
 child.on('message',m=>{if(m.type==='ready')readyResolve(m);else resultResolve(m);});
 child.once('error',e=>{readyReject(e);resultReject(e);});
 child.once('exit',code=>{const e=Error('Peer exited: '+code);readyReject(e);resultReject(e);});
 return {child,ready,result};
}
async function exercise(wrongPin=false){
 const a=worker(),b=worker();let timer;
 try{
  return await Promise.race([(async()=>{
   const [x,y]=await Promise.all([a.ready,b.ready]);
   assert.notEqual(a.child.pid,b.child.pid);assert.notEqual(x.port,y.port);
   const context={channel:randomBytes(48).toString('hex'),generation:0,previous:'0'.repeat(96)};
   const pinned=wrongPin?{...x.publicKeys,classical:generateKeyPairSync('ec',{namedCurve:'prime256v1'}).publicKey.export({format:'der',type:'spki'}).toString('base64url')}:x.publicKeys;
   // The parent distributes public configuration only and never relays UDP.
   b.child.send({type:'start',role:'responder',peer:pinned,port:x.port,context});
   a.child.send({type:'start',role:'initiator',peer:y.publicKeys,port:y.port,context});
   return await Promise.all([a.result,b.result]);
  })(),new Promise((_,reject)=>{timer=setTimeout(()=>reject(Error('Independent peer test deadline')),10000);})]);
 }finally{clearTimeout(timer);for(const w of [a,b])if(w.child.exitCode===null&&w.child.signalCode===null)w.child.kill();}
}
test('two independent OS processes negotiate P-256/ML-DSA and ML-KEM session without PSK or private-key IPC',{timeout:12000},async t=>{
 const [a,b]=await exercise();
 assert.equal(a.type,'agreed');assert.equal(b.type,'agreed');
 assert.match(a.commitment,/^[a-f0-9]{64}$/);assert.equal(a.commitment,b.commitment);assert.equal(a.transcript,b.transcript);
 t.diagnostic('INDEPENDENT_UDP_SESSION_EVIDENCE '+JSON.stringify({processes:2,sharedBootstrapSecret:false,privateKeyIPC:false,matchedSession:true,physicalHosts:1,releaseAuthorized:false}));
});
test('independent processes refuse substituted pinned identity',{timeout:12000},async()=>{
 const [a,b]=await exercise(true);assert.equal(a.type,'refused');assert.equal(b.type,'refused');
});
