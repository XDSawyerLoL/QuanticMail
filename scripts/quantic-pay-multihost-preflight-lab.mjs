#!/usr/bin/env node
// Operator-driven multi-host preflight, LAB ONLY. The remote witnesses must
// already exist and run independently; this does not deploy any services,
// prove physical independence, or grant permission for real money.
import {openShardedPayLab} from '../lib/quantic/pay-sharded-lab.mjs';
import {openRemoteShardWitnessCoordinatorLab} from '../lib/quantic/pay-shard-witness-mtls-coordinator-lab.mjs';
import {openPayWitnessMtlsClientLab} from '../lib/quantic/pay-witness-mtls-lab.mjs';
import {readWitnessPrivateFileLab} from '../lib/quantic/pay-witness-private-file-lab.mjs';

const hex=v=>typeof v==='string'&&/^[a-f0-9]{64}$/.test(v);
const exact=(o,k)=>o&&typeof o==='object'&&!Array.isArray(o)
 &&Object.keys(o).length===k.length&&k.every(s=>Object.hasOwn(o,s));
const check=v=>{if(!v)throw Error('Remote witness preflight refused');};
const path=process.env.QUANTIC_PAY_MULTHOST_PREFLIGHT_CONFIG;
let files=[];
try{
 const bytes=readWitnessPrivateFileLab(path,{maxBytes:524288});
 let cfg;
 try{cfg=JSON.parse(bytes.toString('utf8'));}finally{bytes.fill(0);}
 check(exact(cfg,['config','options','shard','witnesses','peers','tls','checkpoint','anchor','allowSingleHostLab']));
 check(typeof cfg.allowSingleHostLab==='boolean'
  &&Array.isArray(cfg.peers)&&cfg.peers.length===4
  &&Array.isArray(cfg.witnesses)&&cfg.witnesses.length===4);
 check(exact(cfg.tls,['keyPath','certPath','caPath']));
 const ledger=openShardedPayLab(cfg.config,cfg.options);
 check(exact(cfg.anchor,['network','shard','height','root'])
  &&cfg.anchor.network===ledger.network&&cfg.anchor.shard===cfg.shard
  &&Number.isSafeInteger(cfg.anchor.height)&&cfg.anchor.height>=0
  &&cfg.anchor.height<=256&&hex(cfg.anchor.root));
 const root=cfg.anchor.height===0?
  ledger.openShard(cfg.shard).snapshot().root:
  ledger.verifyCheckpoint(cfg.checkpoint,cfg.anchor).root;
 check(root===cfg.anchor.root&&(cfg.anchor.height===0?cfg.checkpoint===null:cfg.checkpoint!==null));
 const endpoints=new Set(),hostnames=new Set(),pins=new Set();
 for(const peer of cfg.peers){
  check(exact(peer,['url','serverCertPin'])&&typeof peer.url==='string'
   &&peer.url.length<512&&hex(peer.serverCertPin));
  const u=new URL(peer.url);
  check(u.protocol==='https:'&&!u.username&&!u.password&&!u.search
   &&!u.hash&&u.pathname==='/v1/witness'&&u.port!=='');
  const canonical=u.host.toLowerCase();
  check(!endpoints.has(canonical)&&!pins.has(peer.serverCertPin));
  endpoints.add(canonical);pins.add(peer.serverCertPin);hostnames.add(u.hostname.toLowerCase());
  if(!cfg.allowSingleHostLab){
   check(!/^(localhost|127\.|\[::1\]$|::1$|0\.0\.0\.0$)/i.test(u.hostname));
  }
 }
 // Distinct DNS/IP names are useful operational checks, NOT hardware attestation.
 if(!cfg.allowSingleHostLab)check(hostnames.size===4);
 files=[
  readWitnessPrivateFileLab(cfg.tls.keyPath,{maxBytes:65536}),
  readWitnessPrivateFileLab(cfg.tls.certPath,{maxBytes:65536}),
  readWitnessPrivateFileLab(cfg.tls.caPath,{maxBytes:65536})
 ];
 const credentials={key:files[0],cert:files[1],ca:files[2]};
 const clients=cfg.peers.map(peer=>openPayWitnessMtlsClientLab({
  url:peer.url,credentials,serverCertPin:peer.serverCertPin,timeoutMs:5000
 }));
 const bridge=openRemoteShardWitnessCoordinatorLab({
  config:cfg.config,options:cfg.options,shard:cfg.shard,
  witnesses:cfg.witnesses,clients
 });
 const result=await bridge.fresh({height:cfg.anchor.height,root:cfg.anchor.root});
 check(result.witnesses>=3);
 process.stdout.write(JSON.stringify({event:'preflight-passed',network:ledger.network,
  shard:cfg.shard,height:result.height,root:result.root,
  verifiedWitnesses:result.witnesses,pinnedEndpoints:4,
  physicalIndependenceVerified:false,realPaymentAuthorized:false,
  simulationOnly:true})+'\n');
}catch{
 // Refuse without echoing private file paths, credentials or remote responses.
 process.stderr.write('Quantic Pay remote witness preflight refused\n');
 process.exitCode=1;
}finally{for(const file of files)file.fill(0);}
