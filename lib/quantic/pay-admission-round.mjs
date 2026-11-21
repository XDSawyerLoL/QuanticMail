// Separate v2 admission round, fixed to one verified history and authority.
// The raw generic round store is not an admission-validation API.
// Trusted provisioning; do not create parallel journals for the same key/height.
import {createRoundCirculationLab} from './pay-circulation-lab.mjs';
import {createPayRoundLab} from './pay-round-lab.mjs';
import {openPersistentPayRound} from './pay-round-store.mjs';
const check=v=>{if(!v)throw Error('Admission round refused');};
export function openAdmissionRound({config,records,directory,authorityPin,classicalPrivateKey,pqPrivateKey,createNew=false,clock=Date.now}){
 const chain=createRoundCirculationLab(structuredClone(config)),history=structuredClone(records);
 check(chain.roundGated);
 const rc=chain.admissionRoundConfig(history),lab=createPayRoundLab(rc);
 const store=openPersistentPayRound({directory,createNew,config:rc,authorityPin,classicalPrivateKey,pqPrivateKey});
 return Object.freeze({
  scope:lab.scope,
  status:store.status,
  changeView:store.changeView,
  prepare({draft,round,viewCertificate=null}){
   const input=structuredClone(draft),d=chain.draft(history,input),now=clock();
   check(Number.isSafeInteger(now)&&now>=input.admissionTime&&now-input.admissionTime<=15000&&input.proposals.every(p=>now<p.intent.expires));
   return store.prepare({round,value:d.scope,viewCertificate});
  },
  commit({draft,certificate}){
   const d=chain.draft(history,draft),qc=lab.prepared(certificate),now=clock();
   check(qc.value===d.scope&&Number.isSafeInteger(now)&&now>=draft.admissionTime&&now-draft.admissionTime<=15000&&draft.proposals.every(p=>now<p.intent.expires));
   return store.commit(qc);
  },
  learn({draft,certificate}){
   const d=chain.draft(history,draft),final=lab.finalized(certificate);
   check(final.value===d.scope);
   const admitted={...structuredClone(draft),admissionCertificate:structuredClone(certificate)};
   chain.admit(history,admitted);
   store.learn(certificate);
   return admitted;
  },
  close:store.close
 });
}
