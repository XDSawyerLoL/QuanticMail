// Offline scoring only; synthetic traffic and temporary test keys.
import {readFileSync} from 'node:fs';
import {resolve,isAbsolute} from 'node:path';
import {createHash} from 'node:crypto';
import {parseLabPcap} from '../lib/quantic/scattering-multihop-observer.mjs';
import {evaluateTimeOnlyLab} from '../lib/quantic/scattering-temporal-correlation-lab.mjs';
import {openReliable} from '../labs/quantic-native/scattering/scattering-reliable-lab.mjs';
import {openEndToEndLab} from '../lib/quantic/scattering-e2e-envelope-lab.mjs';
const check=(ok,msg)=>{if(!ok)throw Error(msg)};
const [dir,profile,mixRaw]=process.argv.slice(2);
check(dir&&isAbsolute(dir)&&['balanced','skewed','sparse'].includes(profile)&&['0','1'].includes(mixRaw),'invalid synthetic profile');
const [aN,bN]=({balanced:[100,100],skewed:[100,20],sparse:[3,1]})[profile];
const n=aN+bN;
const read=name=>readFileSync(resolve(dir,name));
const json=name=>JSON.parse(read(name).toString().trim().split('\n').at(-1));
function native(name,count){
 const m=/planned=(\d+) sent=(\d+) missed=(\d+)/.exec(read(name).toString());
 check(m&&+m[1]===count&&+m[2]===count&&+m[3]===0,'native cadence failed '+name);
 return {planned:+m[1],sent:+m[2],missed:+m[3]};
}
function trace(name,hopKey,e2eKey,expectedPackets,expectedData,expectedSource=null){
 const pc=parseLabPcap(read(name),{includeCiphertext:true});
 check(pc.packets.length===expectedPackets,'incomplete capture '+name);
 const authenticated=new Map(),wire=new Set();
 for(const p of pc.packets){
  check(!wire.has(p.hash),'duplicate captured ciphertext '+name);wire.add(p.hash);
  const hop=openReliable(hopKey,p.ciphertext);
  p.ciphertext.fill(0);
  if(!hop||hop.seq===null)continue;
  check(hop.data.length===92,'wrong authenticated inner size');
  const inner=openEndToEndLab(e2eKey,hop.data);
  check(inner!==null,'inner authentication failure '+name);
  const id=inner.senderId+':'+inner.seq;
  check(expectedSource===null||inner.senderId===expectedSource,'wrong source '+name);
  check(!authenticated.has(id),'duplicate authenticated identity '+name);
  const innerHash=createHash('sha256').update(hop.data).digest('hex');
  authenticated.set(id,{innerHash,time:p.timestampMs,sender:inner.senderId});
  hop.data.fill(0);inner.data.fill(0);
 }
 check(authenticated.size===expectedData,'incomplete authenticated trace '+name);
 return {wire,authenticated,count:pc.packets.length};
}
function compare(before,after){
 check(before.authenticated.size===after.authenticated.size,'different message count');
 const delays=[];
 for(const [id,p] of before.authenticated){
  const q=after.authenticated.get(id);
  check(q&&q.innerHash===p.innerHash&&q.time>=p.time,'altered or missing inner ciphertext');
  delays.push(q.time-p.time);
 }
 delays.sort((a,b)=>a-b);
 const quantile=q=>+delays[Math.ceil(q*delays.length)-1].toFixed(3);
 const directMatches=[...before.wire].filter(h=>after.wire.has(h)).length;
 check(directMatches===0,'outer ciphertext equality leak');
 return {authenticatedUnchangedInner:delays.length,outerCiphertextMatches:directMatches,p50Ms:quantile(.5),p95Ms:quantile(.95),maxMs:quantile(1)};
}
const keys=['a','b','mid','out','e2e'].map(x=>read(x+'.key'));
try{
 check(keys.every(x=>x.length===32)&&new Set(keys.map(x=>x.toString('hex'))).size===5,'keys must be distinct');
 const [ka,kb,km,ko,ke]=keys;
 const relay1=json('relay.json'),relay2=json('relay2.json'),receiver=json('receive.json');
 const pacer1=native('mid.report',550),pacer2=native('egress.report',700);
 check(relay1.ingressA===aN&&relay1.ingressB===bN&&relay1.spooled===n&&relay1.spoolErrors===0&&relay1.rejected===0,'relay1 evidence failed');
 check(relay2.received===550&&relay2.authenticated===n&&relay2.spooled===n&&relay2.coverOrInvalid===550-n&&relay2.duplicates===0&&relay2.invalid===0&&relay2.spoolErrors===0&&relay2.mix===(mixRaw==='1'),'relay2 evidence failed');
 check(receiver.received===700&&receiver.authenticatedE2E===n&&receiver.authenticatedHop===n&&receiver.perSender.A===aN&&receiver.perSender.B===bN&&receiver.duplicates===0&&receiver.invalidInner===0,'recipient evidence failed');
 const a=trace('a.pcap',ka,ke,100,aN,0),b=trace('b.pcap',kb,ke,100,bN,1);
 const mid=trace('mid.pcap',km,ke,550,n),out=trace('out.pcap',ko,ke,700,n);
 const combined={wire:new Set([...a.wire,...b.wire]),authenticated:new Map([...a.authenticated,...b.authenticated])};
 check(combined.authenticated.size===n&&combined.wire.size===200,'source trace overlap');
 const hop1=compare(combined,mid),hop2=compare(mid,out),endToEnd=compare(combined,out);
 const observer=evaluateTimeOnlyLab({captureA:read('a.pcap'),captureB:read('b.pcap'),captureEgress:read('out.pcap'),outputHopKey:ko,endToEndKey:ke,inputHopAKey:ka,inputHopBKey:kb});
 check(observer.truth.A===aN&&observer.truth.B===bN&&observer.observedPackets===700,'incorrect scoring truth');
 if(profile==='sparse')check(relay1.timedFlushes>0&&relay2.timedFlushes>0,'missing sparse timer evidence');
 console.log(JSON.stringify({experiment:'two-successive-native-relays',profile,secondMix:mixRaw==='1',
  physicalHosts:1,networkNamespaces:5,sharedFilesystem:true,endpointKeySuppliedToRelays:false,
  native:{first:pacer1,second:pacer2},authenticated:n,relay1,relay2,
  hop1,hop2,endToEnd,
  latencyScreen:{p95TargetMs:500,passed:endToEnd.p95Ms<=500},
  timingAttacks:observer.fifoQueueTimingAttack.scenarios,
  limitations:'Both relays can see identical inner ciphertext if they collude; the lab does not prove compromised-relay anonymity or physical key isolation.',
  releaseAuthorized:false},null,2));
}finally{for(const k of keys)k.fill(0);}
