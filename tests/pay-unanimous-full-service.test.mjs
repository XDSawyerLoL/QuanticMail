import test from 'node:test';
import assert from 'node:assert/strict';
import {spawn,execFileSync} from 'node:child_process';
import {createServer} from 'node:net';
import {generateKeyPairSync,createHash,randomBytes,sign} from 'node:crypto';
import {mkdtempSync,realpathSync,writeFileSync,chmodSync,rmSync,cpSync,readdirSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {createRoundCirculationLab} from '../lib/quantic/pay-circulation-lab.mjs';
import {createPayRoundLab} from '../lib/quantic/pay-round-lab.mjs';
import {createPayAnchorClient} from '../lib/quantic/pay-anchor-client.mjs';
import {createCommitteeSession} from '../lib/quantic/pay-committee-session.mjs';
import {collectCommitteeVotes} from '../lib/quantic/pay-committee-quorum.mjs';
const replicaScript=fileURLToPath(new URL('../scripts/serve-pay-replica-lab.mjs',import.meta.url));
const anchorScript=fileURLToPath(new URL('../scripts/serve-pay-anchor-lab.mjs',import.meta.url));
const sha=b=>createHash('sha256').update(b).digest('hex');
const spki=k=>k.publicKey.export({format:'der',type:'spki'});
const pair=type=>({cl:type==='ec'?generateKeyPairSync('ec',{namedCurve:'prime256v1'}):generateKeyPairSync(type),pq:generateKeyPairSync('ml-dsa-65')});
const pub=k=>({pin:sha(spki(k.cl)),publicKey:spki(k.cl).toString('base64url'),pqPin:sha(spki(k.pq)),pqPublicKey:spki(k.pq).toString('base64url')});
async function port(){const s=createServer();await new Promise(r=>s.listen(0,'127.0.0.1',r));const p=s.address().port;await new Promise(r=>s.close(r));return p;}
function privateJson(path,value){writeFileSync(path,JSON.stringify(value),{mode:0o600,flag:'wx'});}
async function stop(m){if(m?.proc&&m.proc.exitCode===null&&m.proc.signalCode===null)await new Promise(r=>{m.proc.once('exit',r);m.proc.kill();});}
async function start(m){
 m.proc=spawn(process.execPath,m.args,{stdio:['ignore','pipe','pipe']});
 await new Promise((res,rej)=>{const timer=setTimeout(()=>rej(Error('startup deadline: '+m.ready)),20000);m.proc.once('error',e=>{clearTimeout(timer);rej(e);});m.proc.once('exit',()=>{clearTimeout(timer);rej(Error('process stopped: '+m.ready));});m.proc.stdout.on('data',b=>{if(b.toString().includes(m.ready)){clearTimeout(timer);res();}});m.proc.stderr.resume();});
}
function restore(src,dst){
 cpSync(src,dst,{recursive:true});
 function fix(p){chmodSync(p,0o700);for(const e of readdirSync(p,{withFileTypes:true})){const q=join(p,e.name);if(e.isDirectory())fix(q);else chmodSync(q,0o600);}}
 fix(dst);
}
// Explicit dedicated runner: 80 persistent service processes, no local signing
// in the transaction coordinator and no synthetic clock or fake anchor.
test('all sixteen strict remote voters each require four distinct durable TLS anchors',{skip:process.platform!=='linux'||process.env.QUANTIC_PAY_FULL_STRICT_TEST!=='1',timeout:600000},async t=>{
 const dir=realpathSync(mkdtempSync(join(tmpdir(),'pay-strict-full-'))),nodes=[],anchors=[],usedPorts=new Set(),usedSecrets=new Set(),certKeys=new Set();
 const wallets=[pair('ec'),pair('ec')],witnesses=Array.from({length:16},()=>pair('ed25519'));
 const config={admissionPolicy:'round-v3-unanimous',wallets:wallets.map((w,i)=>({id:i?'demo-bob':'demo-alice',initialCents:i?0:10000,...pub(w)})),witnesses:witnesses.map(pub)};
 const lab=createRoundCirculationLab(config),network=lab.snapshot([]).network;
 async function uniquePort(){
  for(let i=0;i<32;i++){const p=await port();if(!usedPorts.has(p)){usedPorts.add(p);return p;}}
  throw Error('port allocation exhausted');
 }
 function secret(){const s=randomBytes(32).toString('hex');assert(!usedSecrets.has(s));usedSecrets.add(s);return s;}
 function session(n){
  return createCommitteeSession({network,authorityPin:n.pin,provision:async request=>({network,authorityPin:n.pin,profile:request.profile,epochId:randomBytes(32).toString('hex'),loopbackPort:n.port,token:n.token,close:async()=>{}})});
 }
 function fresh(n){n.session?.close();n.session=session(n);}
 const clients=()=>nodes.map(n=>({authorityPin:n.pin,client:n.session}));
 const timed=async(name,fn)=>{const start=performance.now();const result=await fn();t.diagnostic(name+' ms='+Math.round(performance.now()-start));return result;};
 async function all(fn){
  const results=await Promise.allSettled(nodes.map(fn));
  const failures=results.flatMap((r,i)=>r.status==='rejected'?[String(i)+': '+r.reason.message]:[]);
  assert.equal(failures.length,0,failures.join('; '));
  return results.map(r=>r.value);
 }
 function proposal(records,payer,payee,cents){
  const now=Date.now(),intent=lab.prepare(records,{payer,payee,cents,nonce:randomBytes(32).toString('hex'),now}),raw=lab.transcript(intent),k=wallets[payer==='demo-alice'?0:1];
  return {proposals:[{intent,signature:sign('sha256',raw,{key:k.cl.privateKey,dsaEncoding:'ieee-p1363'}).toString('base64url'),pqSignature:sign(null,raw,k.pq.privateKey).toString('base64url')}],admissionTime:now};
 }
 try{
  for(let i=0;i<16;i++){
   const pin=config.witnesses[i].pin,initial={format:'quantic-pay-external-checkpoint/v1',network,authorityPin:pin,sequence:0,root:network,admission:null,financial:null};
   const n={pin,port:await uniquePort(),token:secret(),anchors:[],directory:join(dir,'replica-'+i),ready:'READY PAY REPLICA LAB'};
   nodes.push(n);
   const file=join(dir,'replica-'+i+'.json'),keyFile=join(dir,'replica-key-'+i+'.pem'),pqKeyFile=join(dir,'replica-pq-'+i+'.pem'),quorumFile=join(dir,'quorum-'+i+'.json');
   writeFileSync(keyFile,witnesses[i].cl.privateKey.export({format:'pem',type:'pkcs8'}),{mode:0o600,flag:'wx'});
   writeFileSync(pqKeyFile,witnesses[i].pq.privateKey.export({format:'pem',type:'pkcs8'}),{mode:0o600,flag:'wx'});
   privateJson(file,{simulationOnly:true,directory:n.directory,chainConfig:config,expectedNetwork:network,authorityKeyFile:keyFile,authorityPin:pin,authorityPQKeyFile:pqKeyFile,authorityPQPin:config.witnesses[i].pqPin,token:n.token,port:n.port});
   execFileSync(process.execPath,[replicaScript,'provision',file],{stdio:'ignore'});
   if(i===0)restore(n.directory,join(dir,'backup-genesis'));
   for(let j=0;j<4;j++){
    const tag=i+'-'+j,serverFile=join(dir,'anchor-'+tag+'.json'),clientFile=join(dir,'anchor-client-'+tag+'.json'),keyFile=join(dir,'anchor-key-'+tag+'.pem'),certFile=join(dir,'anchor-cert-'+tag+'.pem'),p=await uniquePort(),token=secret();
    execFileSync('openssl',['req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:prime256v1','-nodes','-keyout',keyFile,'-out',certFile,'-days','2','-subj','/CN=127.0.0.1','-addext','subjectAltName=IP:127.0.0.1'],{stdio:'ignore'});
    chmodSync(keyFile,0o600);chmodSync(certFile,0o600);
    const keyHash=sha(execFileSync('openssl',['x509','-in',certFile,'-pubkey','-noout']));assert(!certKeys.has(keyHash));certKeys.add(keyHash);
    privateJson(serverFile,{simulationOnly:true,directory:join(dir,'anchor-'+tag),initial,port:p,token,keyFile,certFile});
    privateJson(clientFile,{simulationOnly:true,network,authorityPin:pin,port:p,token,certFile});
    execFileSync(process.execPath,[anchorScript,'provision',serverFile],{stdio:'ignore'});
    const a={clientFile,args:[anchorScript,'serve',serverFile],ready:'READY PAY ANCHOR LAB'};
    anchors.push(a);n.anchors.push(a);await start(a);
   }
   privateJson(quorumFile,{simulationOnly:true,network,authorityPin:pin,members:n.anchors.map(a=>a.clientFile)});
   n.args=[replicaScript,'serve-quorum-anchored',file,quorumFile];await start(n);fresh(n);
  }
  assert.equal(anchors.length,64);assert.equal(nodes.length,16);assert.equal(certKeys.size,64);
  assert.equal(usedPorts.size,80);assert.equal(usedSecrets.size,80);
  assert.equal(new Set([...nodes,...anchors].map(n=>n.proc.pid)).size,80);
  for(const status of await all(n=>n.session.status()))assert.equal(status.sequence,0);
  // All votes below originate in the remote guarded processes.
  const draft=proposal([],'demo-alice','demo-bob',7500),a=createPayRoundLab(lab.admissionRoundConfig([])),av=lab.draft([],draft).scope;
  assert.equal(a.committee.quorum,16);
  const collect=(roundLab,phase,value,invoke)=>collectCommitteeVotes({lab:roundLab,authorities:clients(),phase,round:0,value,invoke});
  const ap=await timed('all 16 admission prepare',()=>collect(a,'prepare',av,c=>c.admissionPrepare({scope:a.scope,input:{draft,round:0}})));
  assert.throws(()=>a.prepared({...ap,votes:ap.votes.slice(0,15)}));
  const ac=await timed('all 16 admission commit',()=>collect(a,'commit',av,c=>c.admissionCommit({scope:a.scope,input:{draft,certificate:ap}})));
  const admission={...draft,admissionCertificate:{prepared:ap,commit:ac}},info=lab.admit([],admission);
  await timed('all 16 admission installation',()=>all(n=>n.session.admit(admission)));
  t.diagnostic('strict full admission age ms='+String(Date.now()-draft.admissionTime));
  const b=createPayRoundLab(info.config),value=info.candidates[0].value;
  const fp=await timed('all 16 financial prepare',()=>collect(b,'prepare',value,c=>c.prepare({scope:b.scope,input:{round:0,value}})));
  const fc=await timed('all 16 financial commit',()=>collect(b,'commit',value,c=>c.commitVote({scope:b.scope,input:fp})));
  assert.throws(()=>b.finalized({prepared:fp,commit:{...fc,votes:fc.votes.slice(0,15)}}));
  const record={admission,certificate:{prepared:fp,commit:fc}},receipt=lab.receipt([],record);
  for(const r of await timed('all 16 settlement',()=>all(n=>n.session.learn(record))))assert.deepEqual(r,receipt);
  for(const status of await all(n=>n.session.status())){
   assert.equal(status.sequence,1);assert.equal(status.root,receipt.root);assert.deepEqual(status.balances,{'demo-alice':2500,'demo-bob':7500});assert.equal(status.totalCents,10000);
  }
  let retained=0;
  for(const n of nodes){
   const values=n.anchors.map(a=>createPayAnchorClient({configFile:a.clientFile,network,authorityPin:n.pin}).read());
   for(const c of values){assert.equal(c.sequence,1);assert.equal(c.root,receipt.root);assert.equal(c.authorityPin,n.pin);assert.deepEqual(c,values[0]);retained++;}
  }
  assert.equal(retained,64);t.diagnostic('80 processes, 16/16 financial roots and 64/64 anchor checkpoints agree');
  // One failed anchor must withhold the next vote. Other 15 voters may
  // prepare; the collector cannot finalize a 15/16 result.
  const n=nodes[15],lost=n.anchors[3];await stop(lost);
  const next=proposal([record],'demo-bob','demo-alice',100),a2=createPayRoundLab(lab.admissionRoundConfig([record])),v2=lab.draft([record],next).scope;
  await assert.rejects(collect(a2,'prepare',v2,c=>c.admissionPrepare({scope:a2.scope,input:{draft:next,round:0}})),/15\/16 verified votes/);
  assert.equal(n.session.sessionStatus().halted,true);
  // Explicit restart with all 4 anchors prior to expiry. No retry after
  // ambiguity except this operator-initiated exact same proposal.
  await stop(n);await start(lost);await start(n);fresh(n);
  assert.equal((await n.session.status()).root,receipt.root);
  // Finally restore a real pre-payment directory while its four anchors
  // retain the settled state. The strict service must refuse startup.
  const old=nodes[0];await stop(old);rmSync(old.directory,{recursive:true,force:true});restore(join(dir,'backup-genesis'),old.directory);
  assert.throws(()=>execFileSync(process.execPath,old.args,{stdio:'ignore',timeout:20000}));
  t.diagnostic('one missing anchor blocks next 16/16 certificate; restored genesis cannot start guarded service');
 }finally{
  for(const n of nodes)if(n.session&&!n.session.sessionStatus().busy)n.session.close();
  await Promise.all(nodes.map(stop));await Promise.all(anchors.map(stop));rmSync(dir,{recursive:true,force:true});
 }
});
