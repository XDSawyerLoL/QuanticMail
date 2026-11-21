// One durable chain and per-height round journals for a fixed authority.
// Trusted provisioning, fixed local directory and trusted admission coordinator.
// No real money, distributed admission consensus, whole-disk rollback defense.
import {createHash,createPublicKey} from 'node:crypto';
import {mkdirSync,realpathSync,lstatSync} from 'node:fs';
import {join,dirname,isAbsolute} from 'node:path';
import {openRoundChain} from './pay-round-chain-store.mjs';
import {openPersistentPayRound} from './pay-round-store.mjs';
import {createPayRoundLab} from './pay-round-lab.mjs';
const check=v=>{if(!v)throw Error('Pay round replica refused');};
const pin=k=>createHash('sha256').update(createPublicKey(k).export({format:'der',type:'spki'})).digest('hex');
const exact=(o,k)=>o&&typeof o==='object'&&Object.keys(o).length===k.length&&k.every(x=>Object.hasOwn(o,x));
export function openPayRoundReplica({directory,config,authorityPin,classicalPrivateKey,pqPrivateKey,createNew=false,clock=Date.now}){
 const stable=structuredClone(config),a=stable.witnesses.find(w=>w.pin===authorityPin);
 check(a&&classicalPrivateKey?.type==='private'&&pqPrivateKey?.type==='private'&&pin(classicalPrivateKey)===authorityPin&&pin(pqPrivateKey)===a.pqPin);
 check(process.platform==='linux'&&typeof directory==='string'&&isAbsolute(directory)&&realpathSync(dirname(directory))===dirname(directory));
 if(createNew===true)mkdirSync(directory,{mode:0o700});else check(createNew===false);
 const st=lstatSync(directory);check(st.isDirectory()&&st.uid===process.getuid()&&(st.mode&0o077)===0&&realpathSync(directory)===directory);
 const chain=openRoundChain({directory:join(directory,'chain'),config:stable,authorityPin,createNew,clock});
 let closed=false;
 const journal=(info,createNew=false)=>openPersistentPayRound({directory:join(directory,'height-'+info.config.height),config:info.config,authorityPin,classicalPrivateKey,pqPrivateKey,createNew});
 function pending(){
  check(!closed);const p=chain.admission();check(p);return p;
 }
 function use(scope,fn){
  const p=pending();check(p.info.scope===scope);
  const j=journal(p.info);try{return fn(j,p);}finally{j.close();}
 }
 try{
  const p=chain.admission();
  if(p){const j=journal(p.info);j.close();}
  return Object.freeze({
   status:()=>{check(!closed);const s=chain.snapshot();return Object.freeze({...s,authorityPin,round:s.pendingScope?use(s.pendingScope,j=>j.status()):null});},
   admit(input){
    check(!closed);
    const {created,info}=chain.admitExact(input);
    // Crash between admission and journal creation means a blocked replica.
    // Missing or partially created journal is NEVER silently recreated.
    const j=journal(info,created);try{return {scope:info.scope,height:info.config.height,authorityPin,simulationOnly:true};}finally{j.close();}
   },
   prepare:({scope,input})=>use(scope,j=>j.prepare(input)),
   changeView:({scope,input})=>use(scope,j=>j.changeView(input)),
   commitVote:({scope,input})=>use(scope,j=>j.commit(input)),
   learn(record){
    check(!closed&&exact(record,['admission','certificate']));
    const saved=structuredClone(record),scope=saved.certificate?.prepared?.scope,p=chain.admission();
    // Exact pending admission only: no alternative scope can bypass local votes.
    if(p){
     check(scope===p.info.scope&&JSON.stringify(saved.admission)===JSON.stringify(p.admission));
     use(scope,j=>{
      const f=createPayRoundLab(p.info.config).finalized(saved.certificate),status=j.status();
      if(status.finalValue===null)j.learn(saved.certificate);else check(status.finalValue===f.value);
     });
     return chain.commit(saved.certificate);
    }
    const s=chain.snapshot();
    const existing=chain.receipts().find(r=>r.scope===scope);
    if(existing){
     check(JSON.stringify(chain.record(existing.sequence).admission)===JSON.stringify(saved.admission));
     return chain.commit(saved.certificate);
    }
    check(s.sequence<32);
    return chain.syncCertified(saved);
   },
   record:height=>{check(!closed);return chain.record(height);},
   close(){if(!closed){closed=true;chain.close();}}
  });
 }catch(e){chain.close();throw e;}
}
