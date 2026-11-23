/** Separate OS processes, coordinator sees ONLY signed public data and AEAD ciphertexts.
 * IPC is a test carrier, NOT a physically independent network or production consensus.
 */
import {fork} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {resolve,dirname} from 'node:path';
import {sha256,lagrangeAtZero,scalarDecode,verifyShare,N} from './proactive-v08-core.mjs';
const workerFile=resolve(dirname(fileURLToPath(import.meta.url)),'proactive-v08-relay.mjs');
export class ProactiveLab {
  constructor(){this.workers=[];this.counter=0;this.epoch=0;this.transcripts=[];this.lastPackets=[];}
  async start(){
    if(this.workers.length)throw new Error('already started');
    for(let i=1;i<=N;i++){
      const child=fork(workerFile,[],{env:{...process.env,QS_V08_LAB_ONLY:'1'},stdio:['ignore','ignore','pipe','ipc'],execArgv:[]});
      child.stderr.on('data',()=>{});
      const worker={child,callbacks:new Map()};
      child.on('message',msg=>{const entry=worker.callbacks.get(msg.id);if(!entry)return;worker.callbacks.delete(msg.id);if(msg.ok)entry.resolve(msg.result);else entry.reject(new Error(msg.error));});
      child.on('exit',()=>{for(const entry of worker.callbacks.values())entry.reject(new Error('relay subprocess exited'));worker.callbacks.clear();});
      this.workers.push(worker);
    }
    try{
      const ids=await Promise.all(this.workers.map((_,i)=>this.request(i,'init',{id:i+1})));
      await Promise.all(this.workers.map((_,i)=>this.request(i,'registry',{entries:ids})));
      return this;
    }catch(e){await this.close();throw e;}
  }
  async request(index,cmd,args={}){
    const w=this.workers[index];if(!w||!w.child.connected)throw new Error('relay disconnected');
    const id=++this.counter;
    return new Promise((resolve,reject)=>{
      const timeout=setTimeout(()=>{w.callbacks.delete(id);reject(new Error('relay timeout '+cmd));},30000);
      w.callbacks.set(id,{resolve:r=>{clearTimeout(timeout);resolve(r);},reject:e=>{clearTimeout(timeout);reject(e);}});
      w.child.send({id,cmd,args},err=>{if(err){const pending=w.callbacks.get(id);if(pending){w.callbacks.delete(id);pending.reject(err);}}});
    });
  }
  async each(cmd,args){return Promise.all(this.workers.map((_,i)=>this.request(i,cmd,args)));}
  async abort(){await Promise.allSettled(this.workers.map((_,i)=>this.request(i,'abort')));}
  async round({mutate}={}){
    const epoch=this.epoch+1,mode=this.epoch===0?'dkg':'refresh';
    try{
      const initialized=await this.each('begin',{epoch});
      const manifests=initialized.map(x=>x.manifest);
      await this.each('manifests',{epoch,manifests});
      const contributions=await this.each('contribute',{epoch,mode});
      const proofs=contributions.map(x=>x.proof);
      const packets=contributions.flatMap(x=>x.packets);
      this.lastPackets=packets.map(p=>structuredClone(p));
      const baseline=packets.map(p=>({from:p.ad.from,to:p.ad.to,epoch,mode,bytes:Buffer.from(p.envelope.ct,'base64').length,packetBytes:Buffer.byteLength(JSON.stringify(p))}));
      if(mutate)mutate(packets,proofs,manifests);
      const responses=await Promise.all(this.workers.map((_,i)=>this.request(i,'stage',{
        epoch,mode,proofs,packets:packets.filter(p=>p.ad.to===i+1)}
      )));
      const acks=responses.map(x=>x.ack);
      const commits=await this.each('commit',{acks});
      if(new Set(commits.map(c=>c.commitmentFingerprint)).size!==1)throw new Error('commitment state disagrees');
      this.transcripts.push(...baseline);
      this.epoch=epoch;
      return {epoch,mode,packetCount:packets.length,
        cipherSizes:[...new Set(baseline.map(v=>v.bytes))],
        packetSizes:[...new Set(baseline.map(v=>v.packetBytes))],
        commitmentFingerprint:sha256(commits[0].commitmentFingerprint),
        coordinatorObservedRawShares:false};
    }catch(e){await this.abort();throw e;}
  }
  async states(){return this.each('state');}
  async recoverForAudit(ids=[1,2,3]){
    if(!Array.isArray(ids)||ids.length!==3||new Set(ids).size!==3)throw new Error('3 distinct relay IDs required');
    const data=await Promise.all(ids.map(id=>this.request(id-1,'recover-for-test')));
    if(new Set(data.map(v=>v.epoch)).size!==1||new Set(data.map(v=>sha256(v.commitments))).size!==1)throw new Error('inconsistent audit epochs');
    for(const p of data)if(!verifyShare(p.commitments,p.x,scalarDecode(p.y),scalarDecode(p.blind)))throw new Error('bad recovery proof');
    return {epoch:data[0].epoch,secret:lagrangeAtZero(data.map(p=>({x:p.x,y:scalarDecode(p.y)}))),shares:data};
  }
  async close(){
    const workers=this.workers;this.workers=[];
    await Promise.all(workers.map(w=>new Promise(resolve=>{
      const child=w.child;
      if(child.exitCode!==null||child.signalCode!==null){resolve();return;}
      const watchdog=setTimeout(()=>child.kill('SIGKILL'),3000);
      child.once('exit',()=>{clearTimeout(watchdog);resolve();});
      child.kill('SIGTERM');
    })));
  }
}
