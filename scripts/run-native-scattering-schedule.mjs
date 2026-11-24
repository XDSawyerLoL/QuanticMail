// No automatic retries or restart of an uncertain epoch.
import {loadPrivateCarrierSchedule,runPrivateCarrierSchedule} from '../standalone-relay/native-scattering-schedule.mjs';
const stop=new AbortController();
for(const s of ['SIGINT','SIGTERM'])process.once(s,()=>stop.abort());
try{
 const [file,pin]=process.argv.slice(2);
 if(process.argv.length!==4)throw Error('Independent schedule digest required');
 const schedule=await loadPrivateCarrierSchedule(file,pin);
 const run=schedule.spec.format==='quantic-private-scattering-overlap/v1'
  ?(await import('../standalone-relay/native-scattering-overlap.mjs')).runOverlapSchedule
  :runPrivateCarrierSchedule;
 const result=await run(schedule,{signal:stop.signal,onSlot:s=>{
  process.stdout.write(JSON.stringify({status:'scheduled-private-carrier-active',labOnly:true,...s})+'\n');
 }});
 process.stdout.write(JSON.stringify(result)+'\n');
}catch{process.stderr.write('Scattering schedule refused or interrupted. Preserve consumed epochs; no automatic resend or fallback.\n');process.exitCode=1;}
