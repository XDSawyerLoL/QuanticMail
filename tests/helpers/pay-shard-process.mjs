// IPC fixture only. Independent OS process per partition, 11 independently
// initialized replicas per process, not 11 independent fault domains.
import {createPrivateKey} from 'node:crypto';
import {openShardedPayLab} from '../../lib/quantic/pay-sharded-lab.mjs';
let coordinator,replicas,keys,shard;
function key(s){return createPrivateKey({key:Buffer.from(s,'base64url'),format:'der',type:'pkcs8'});}
function call(msg){
 if(msg.op==='init'){
  if(coordinator)throw Error('already initialized');
  shard=msg.shard;const config=msg.config;keys=msg.keys.map(k=>({authorityPin:k.pin,classicalPrivateKey:key(k.cl),pqPrivateKey:key(k.pq)}));
  if(keys.length!==11)throw Error('fixture requires eleven votes');
  coordinator=openShardedPayLab(config).openShard(shard);
  replicas=keys.map(()=>openShardedPayLab(config).openShard(shard));
  return {pid:process.pid,snapshot:coordinator.snapshot()};
 }
 if(!coordinator)throw Error('not initialized');
 if(msg.op==='snapshot')return coordinator.snapshot();
 if(msg.op==='certify'){
  const ops=msg.operations,p=coordinator.proposal(ops);
  const voters=replicas.map((r,i)=>r.openAuthority(keys[i]));
  const prepared={scope:p.scope,round:0,value:p.value,votes:voters.map(v=>v.prepare(ops))};
  const cert={prepared,commit:{scope:p.scope,round:0,value:p.value,votes:voters.map(v=>v.commit(prepared))}};
  const receipts=coordinator.finalize(ops,cert),snapshot=coordinator.snapshot();
  for(const r of replicas){r.finalize(ops,cert);if(JSON.stringify(r.snapshot())!==JSON.stringify(snapshot))throw Error('divergent replica');}
  return {pid:process.pid,receipts,snapshot};
 }
 throw Error('unknown operation');
}
process.on('message',m=>{try{process.send({id:m.id,ok:true,result:call(m)});}catch{process.send({id:m.id,ok:false});}});
